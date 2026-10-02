"""Config window, mapping dialog, peer picker."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QProgressBar, QPushButton,
    QSpinBox, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

from . import integration


def fingerprint(pid: str) -> str:
    return " ".join(pid[i:i + 4] for i in range(0, 16, 4)).upper()


def human(n) -> str:
    if n is None:
        return "?"
    n = float(n)
    for u in ("o", "Ko", "Mo", "Go", "To"):
        if n < 1024 or u == "To":
            return f"{n:.0f} {u}" if u == "o" else f"{n:.1f} {u}"
        n /= 1024


def peer_label(info: dict) -> str:
    return f"{info['name']}  ({info['os']}, {info['uid']}:{info['gid']})"


class PeerPicker(QDialog):
    """Pick the recipient of a send operation."""

    def __init__(self, peers, paths, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Envoyer avec LanShare")
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
        lay = QVBoxLayout(self)
        names = ", ".join(p.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] for p in paths[:3]) + ("…" if len(paths) > 3 else "")
        lay.addWidget(QLabel(f"Envoyer <b>{len(paths)}</b> élément(s) ({names}) à :"))
        self.list = QListWidget()
        for p in peers:
            if p["blocked"]:
                continue
            it = QListWidgetItem(("● " if p["online"] else "○ ") + peer_label(p["info"]))
            it.setData(Qt.ItemDataRole.UserRole, p["info"]["id"])
            self.list.addItem(it)
        if self.list.count():
            self.list.setCurrentRow(0)
        self.list.itemDoubleClicked.connect(lambda *_: self.accept())
        lay.addWidget(self.list)
        if not self.list.count():
            lay.addWidget(QLabel("Aucun client associé. Ouvrez la configuration pour en ajouter."))
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        self.resize(380, 300)

    def chosen(self):
        it = self.list.currentItem()
        return it.data(Qt.ItemDataRole.UserRole) if it else None


class MapDialog(QDialog):
    """Edit the remote->local uid/gid remapping applied when receiving from a peer."""

    def __init__(self, peer, me, parent=None):
        super().__init__(parent)
        info = peer["info"]
        self.setWindowTitle(f"Mapping uid/gid — {info['name']}")
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(
            f"Distant : <b>{info['uid']}:{info['gid']}</b> ({info['os']}) — Local : <b>{me['uid']}:{me['gid']}</b> ({me['os']})<br>"
            "Les fichiers reçus dont le propriétaire distant figure dans la table sont attribués à l'id local indiqué.<br>"
            "<i>Appliqué uniquement sous Unix et avec les droits nécessaires (root / CAP_CHOWN) ; "
            "ignoré sous Windows (le propriétaire est l'utilisateur local).</i>"))
        self.tables = {}
        tabs = QTabWidget()
        for key, title in (("uid_map", "uid"), ("gid_map", "gid")):
            w = QWidget()
            v = QVBoxLayout(w)
            t = QTableWidget(0, 2)
            t.setHorizontalHeaderLabels([f"{title} distant", f"{title} local"])
            t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            for k, val in sorted((int(k), v) for k, v in peer[key].items()):
                self._row(t, k, val)
            h = QHBoxLayout()
            add, rem = QPushButton("Ajouter"), QPushButton("Supprimer")
            add.clicked.connect(lambda _=False, t=t: self._row(t, info["uid"] if t is self.tables.get("uid_map") else info["gid"], 0))
            rem.clicked.connect(lambda _=False, t=t: t.removeRow(t.currentRow()))
            h.addWidget(add); h.addWidget(rem); h.addStretch()
            v.addWidget(t); v.addLayout(h)
            tabs.addTab(w, title)
            self.tables[key] = t
        lay.addWidget(tabs)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        self.resize(480, 420)

    @staticmethod
    def _row(t, a, b):
        r = t.rowCount()
        t.insertRow(r)
        for c, v in enumerate((a, b)):
            sp = QSpinBox()
            sp.setRange(0, 2**31 - 1)
            sp.setValue(int(v))
            t.setCellWidget(r, c, sp)

    def result_maps(self):
        out = {}
        for key, t in self.tables.items():
            out[key] = {str(t.cellWidget(r, 0).value()): t.cellWidget(r, 1).value() for r in range(t.rowCount())}
        return out


class ConfigWindow(QWidget):
    def __init__(self, ctl, parent=None):
        super().__init__(parent)
        self.ctl = ctl
        self.state = {}
        self.setWindowTitle("LanShare — Configuration")
        self.resize(760, 480)
        lay = QVBoxLayout(self)
        self.tabs = QTabWidget()
        lay.addWidget(self.tabs)

        # --- clients
        w = QWidget(); v = QVBoxLayout(w)
        self.peers = self._table(["Nom", "Empreinte", "Système", "uid:gid", "État"])
        v.addWidget(self.peers)
        h = QHBoxLayout()
        self.b_block = QPushButton("Bloquer / Débloquer")
        self.b_map = QPushButton("Mapper uid/gid…")
        self.b_rm = QPushButton("Retirer")
        for b in (self.b_block, self.b_map, self.b_rm):
            h.addWidget(b)
        h.addStretch()
        v.addLayout(h)
        self.b_block.clicked.connect(self._block)
        self.b_map.clicked.connect(self._map)
        self.b_rm.clicked.connect(self._remove)
        self.tabs.addTab(w, "Clients")

        # --- discovery
        w = QWidget(); v = QVBoxLayout(w)
        v.addWidget(QLabel("Machines détectées et demandes d'association. Associez-vous des deux côtés "
                           "(vérifiez l'empreinte à voix haute) pour échanger vos certificats."))
        self.disc = self._table(["Nom", "Empreinte", "Système", "uid:gid", "Adresse", "État"])
        v.addWidget(self.disc)
        h = QHBoxLayout()
        self.b_search = QPushButton("Rechercher")
        self.b_add = QPushButton("Associer")
        self.b_ignore = QPushButton("Ignorer la demande")
        for b in (self.b_search, self.b_add, self.b_ignore):
            h.addWidget(b)
        h.addStretch()
        v.addLayout(h)
        self.b_search.clicked.connect(lambda: self.ctl.call("search"))
        self.b_add.clicked.connect(self._pair)
        self.b_ignore.clicked.connect(self._ignore)
        self.tabs.addTab(w, "Découverte")

        # --- transfers
        w = QWidget(); v = QVBoxLayout(w)
        self.xf = self._table(["", "Fichier", "Client", "Progression", "État"])
        v.addWidget(self.xf)
        h = QHBoxLayout()
        for label, cmd in (("Pause", "pause"), ("Reprendre / Réessayer", "resume"), ("Annuler", "cancel")):
            b = QPushButton(label)
            b.clicked.connect(lambda _=False, c=cmd: self._xfer_cmd(c))
            h.addWidget(b)
        h.addStretch()
        v.addLayout(h)
        self.tabs.addTab(w, "Transferts")
        self.rows = {}

        # --- settings
        w = QWidget(); f = QFormLayout(w)
        self.name = QLineEdit()
        self.c_bcast = QCheckBox("Diffuser ma présence sur le réseau (broadcast) et répondre aux recherches")
        self.c_exch = QCheckBox("Service d'échange (accepter les connexions entrantes)")
        self.c_enc = QCheckBox("Exiger le chiffrement (TLS 1.3) — si l'un des deux le demande, le transfert est chiffré")
        self.me = QLabel()
        self.me.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        f.addRow("Nom affiché", self.name)
        f.addRow(self.c_bcast); f.addRow(self.c_exch); f.addRow(self.c_enc)
        f.addRow("Cette machine", self.me)
        bi = QPushButton("Installer dans les menus contextuels")
        bu = QPushButton("Retirer des menus contextuels")
        bi.clicked.connect(lambda: self._integrate(True))
        bu.clicked.connect(lambda: self._integrate(False))
        hh = QHBoxLayout(); hh.addWidget(bi); hh.addWidget(bu); hh.addStretch()
        f.addRow("Explorateur de fichiers", hh)
        self.name.editingFinished.connect(lambda: self.ctl.call("set_settings", name=self.name.text()))
        self.c_bcast.clicked.connect(lambda v: self.ctl.call("set_settings", broadcast=v))
        self.c_exch.clicked.connect(lambda v: self.ctl.call("set_settings", exchange=v))
        self.c_enc.clicked.connect(lambda v: self.ctl.call("set_settings", require_encryption=v))
        self.tabs.addTab(w, "Paramètres")

    @staticmethod
    def _table(headers):
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.horizontalHeader().setStretchLastSection(True)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        t.verticalHeader().hide()
        return t

    @staticmethod
    def _fill(t, rows, ids):
        sel = None
        cur = t.currentRow()
        if 0 <= cur < t.rowCount():
            sel = t.item(cur, 0).data(Qt.ItemDataRole.UserRole)
        t.setRowCount(len(rows))
        for r, (row, pid) in enumerate(zip(rows, ids)):
            for c, v in enumerate(row):
                it = QTableWidgetItem(str(v))
                it.setData(Qt.ItemDataRole.UserRole, pid)
                t.setItem(r, c, it)
            if pid == sel:
                t.selectRow(r)

    @staticmethod
    def _selected(t):
        r = t.currentRow()
        return t.item(r, 0).data(Qt.ItemDataRole.UserRole) if r >= 0 else None

    def update_state(self, st):
        self.state = st
        s = st["settings"]
        if not self.name.hasFocus():
            self.name.setText(s["name"])
        for cb, k in ((self.c_bcast, "broadcast"), (self.c_exch, "exchange"), (self.c_enc, "require_encryption")):
            cb.setChecked(s[k])
        me = st["identity"]
        self.me.setText(f"{me['os']} — uid:gid {me['uid']}:{me['gid']} — empreinte {fingerprint(me['id'])} — tcp {st['tcp_port']}")
        rows, ids = [], []
        for p in st["peers"]:
            i = p["info"]
            state = "bloqué" if p["blocked"] else ("en ligne" if p["online"] else "hors ligne")
            rows.append([i["name"], fingerprint(i["id"]), i["os"], f"{i['uid']}:{i['gid']}", state])
            ids.append(i["id"])
        self._fill(self.peers, rows, ids)
        rows, ids, seen = [], [], set()
        for p in st["pending_pairs"]:
            i = p
            rows.append([i["name"], fingerprint(i["id"]), i["os"], f"{i['uid']}:{i['gid']}", "—", "demande reçue"])
            ids.append(i["id"]); seen.add(i["id"])
        for d in st["discovered"]:
            i = d["info"]
            if d["paired"] or i["id"] in seen:
                continue
            rows.append([i["name"], fingerprint(i["id"]), i["os"], f"{i['uid']}:{i['gid']}", d["addr"],
                         "en attente de l'autre côté" if d["intent"] else "détecté"])
            ids.append(i["id"])
        self._fill(self.disc, rows, ids)
        self.sync_transfers(st)

    def _peer(self, pid):
        return next((p for p in self.state.get("peers", []) if p["info"]["id"] == pid), None)

    def _block(self):
        pid = self._selected(self.peers)
        p = self._peer(pid)
        if p:
            self.ctl.call("peer_block", id=pid, blocked=not p["blocked"])

    def _remove(self):
        pid = self._selected(self.peers)
        p = self._peer(pid)
        if p and QMessageBox.question(self, "Retirer", f"Retirer {p['info']['name']} ? Il faudra se ré-associer.") == QMessageBox.StandardButton.Yes:
            self.ctl.call("peer_remove", id=pid)

    def _map(self):
        pid = self._selected(self.peers)
        p = self._peer(pid)
        if not p:
            return
        dlg = MapDialog(p, self.state["identity"], self)
        if dlg.exec():
            self.ctl.call("peer_map", id=pid, **dlg.result_maps())

    def _pair(self):
        pid = self._selected(self.disc)
        if pid:
            self.pair(pid)

    def pair(self, pid):
        def done(m):
            if not m["ok"]:
                QMessageBox.warning(self, "Association", m["error"])
        self.ctl.call("pair_add", done, id=pid)

    def _ignore(self):
        pid = self._selected(self.disc)
        if pid:
            self.ctl.call("pair_reject", id=pid)

    def _xfer_cmd(self, cmd):
        x = self._selected(self.xf)
        if x:
            self.ctl.call(cmd, lambda m: m.get("ok") or QMessageBox.warning(self, "Transfert", m.get("error", "")), xfer=x)

    def _integrate(self, on):
        try:
            done = integration.install(on)
            QMessageBox.information(self, "Menus contextuels", ("Installé :\n" if on else "Retiré :\n") + "\n".join(done))
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "Menus contextuels", str(e))

    # ---- transfers table
    STATES = {
        "waiting": "en attente", "running": "en cours", "retrying": "interrompu — nouvelle tentative",
        "paused": "en pause", "interrupted": "interrompu (reprise possible)", "failed": "échec (réessayer possible)",
        "cancelled": "annulé",
    }

    def _row(self, x):
        if x in self.rows:
            return self.rows[x]
        r = self.xf.rowCount()
        self.xf.insertRow(r)
        bar = QProgressBar()
        bar.setRange(0, 1000)
        self.xf.setCellWidget(r, 3, bar)
        for c in (0, 1, 2, 4):
            self.xf.setItem(r, c, QTableWidgetItem(""))
        for c in (0, 1, 2, 4):
            self.xf.item(r, c).setData(Qt.ItemDataRole.UserRole, x)
        self.rows[x] = r
        return r

    def _describe(self, r, out, name, kind, size, peer):
        self.xf.item(r, 0).setText("⬆" if out else "⬇")
        self.xf.item(r, 1).setText(f"{name}" + ("/" if kind == "dir" else "") + f" ({human(size)})")
        self.xf.item(r, 2).setText(peer)
        if size is None:
            self.xf.cellWidget(r, 3).setRange(0, 0)

    def sync_transfers(self, st):
        """Rebuild rows of unfinished transfers known to the daemon (e.g. after a UI restart)."""
        for t in st.get("transfers", []):
            if t["tid"] in self.rows:
                continue
            r = self._row(t["tid"])
            self._describe(r, t["out"], t["name"], t["kind"], t["size"], self._peer_name(t["peer"]))
            self.xf.item(r, 4).setText(self.STATES.get(t["state"], t["state"]))

    def _peer_name(self, pid):
        p = self._peer(pid)
        return p["info"]["name"] if p else pid[:8]

    def xfer_event(self, ev):
        x, kind = ev["xfer"], ev["event"]
        if x not in self.rows and kind not in ("xfer_start", "incoming", "xfer_state", "progress", "done"):
            return
        if x not in self.rows and kind in ("progress", "done", "xfer_state") and "name" not in ev:
            return  # unknown transfer (not announced yet)
        r = self._row(x)
        text, bar = self.xf.item(r, 4), self.xf.cellWidget(r, 3)
        if kind in ("xfer_start", "incoming") or (kind == "xfer_state" and "name" in ev):
            self._describe(r, kind == "xfer_start" or ev.get("dir") == "out", ev["name"], ev["kind"], ev.get("size"), ev.get("peer_name", ""))
            text.setText("à accepter" if kind == "incoming" else self.STATES["waiting"])
        if kind == "xfer_state":
            s = ev["state"]
            label = self.STATES.get(s, s)
            if s == "retrying" and ev.get("error"):
                label += f" ({ev['error']}" + (f", dans {ev['retry_in']} s" if ev.get("retry_in") else "") + ")"
            elif s == "interrupted" and ev.get("error"):
                label += f" ({ev['error']})"
            elif s == "running" and ev.get("resumed"):
                label = "reprise à " + human(ev.get("offset"))
            text.setText(label)
        elif kind == "progress":
            if ev.get("total"):
                bar.setRange(0, 1000)
                bar.setValue(min(1000, int(ev["bytes"] * 1000 / max(ev["total"], 1))))
            else:
                bar.setRange(0, 0)
        elif kind == "done":
            ok = ev["ok"]
            text.setText("terminé" if ok else f"échec : {ev.get('error', '')}")
            bar.setRange(0, 1000)
            if ok:
                bar.setValue(1000)
