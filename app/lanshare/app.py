"""System tray application: menu, drop zone, notifications, single instance."""
import json
import os
import sys
from pathlib import Path

from PySide6.QtCore import QPoint, QStandardPaths, Qt, QTimer
from PySide6.QtGui import QAction, QColor, QCursor, QIcon, QPainter, QPen, QPixmap, QPolygonF
from PySide6.QtCore import QPointF
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QMenu, QMessageBox, QSystemTrayIcon, QWidget,
)

from .ipc import DaemonClient
from .widgets import ConfigWindow, PeerPicker, fingerprint, human, peer_label

SERVER_NAME = f"lanshare-ui-{os.environ.get('USER') or os.environ.get('USERNAME') or 'user'}"


def make_icon(color="#2b7de9", badge=None) -> QIcon:
    pm = QPixmap(64, 64)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor(color))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(4, 4, 56, 56, 14, 14)
    p.setBrush(QColor("white"))
    p.drawPolygon(QPolygonF([QPointF(14, 24), QPointF(34, 24), QPointF(34, 14), QPointF(52, 28), QPointF(34, 42), QPointF(34, 32), QPointF(14, 32)]))
    p.drawPolygon(QPolygonF([QPointF(50, 40), QPointF(30, 40), QPointF(30, 34), QPointF(12, 46), QPointF(30, 56), QPointF(30, 50), QPointF(50, 50)]))
    if badge:
        p.setBrush(QColor(badge))
        p.drawEllipse(40, 40, 22, 22)
    p.end()
    return QIcon(pm)


class DropZone(QWidget):
    """Small always-on-top target. Qt/OS tray icons cannot receive drops, so this stands in for them."""

    def __init__(self, on_drop):
        super().__init__()
        self.on_drop = on_drop
        self.setWindowFlags(Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAcceptDrops(True)
        self.resize(84, 84)
        self.hover = False
        self._drag = None
        self.setToolTip("Déposez des fichiers/dossiers ici pour les envoyer")

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QColor(43, 125, 233, 230 if self.hover else 170))
        p.setPen(QPen(QColor("white"), 2, Qt.PenStyle.DashLine))
        p.drawRoundedRect(3, 3, self.width() - 6, self.height() - 6, 16, 16)
        p.setPen(QColor("white"))
        p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "⇪\nDéposer")

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            self.hover = True
            self.update()
            e.acceptProposedAction()

    def dragLeaveEvent(self, _):
        self.hover = False
        self.update()

    def dropEvent(self, e):
        self.hover = False
        self.update()
        paths = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.on_drop(paths)

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._drag = e.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if self._drag is not None:
            self.move(e.globalPosition().toPoint() - self._drag)

    def mouseReleaseEvent(self, _):
        self._drag = None

    def contextMenuEvent(self, e):
        m = QMenu(self)
        m.addAction("Masquer", self.hide)
        m.exec(e.globalPos())


class TrayApp:
    def __init__(self, app: QApplication, cfg=None, initial_paths=None):
        self.app = app
        self.state: dict = {}
        self.pending_msg = None  # callable run when the tray notification is clicked
        self.incoming: dict[str, dict] = {}
        self.buffer: list[str] = []
        self._told: set[str] = set()
        self.ctl = DaemonClient(cfg)
        self.win = ConfigWindow(self.ctl)
        self.drop = DropZone(self.send_paths)

        self.tray = QSystemTrayIcon(make_icon("#8a8a8a"), app)
        self.tray.setToolTip("LanShare — connexion au service…")
        self.menu = QMenu()
        self.tray.setContextMenu(self.menu)
        self.tray.activated.connect(self._tray_click)
        self.tray.messageClicked.connect(self._msg_clicked)
        self.tray.show()
        self._build_menu()

        self.ctl.ready.connect(self._on_ready)
        self.ctl.lost.connect(self._on_lost)
        self.ctl.event.connect(self._on_event)
        self.ctl.connect_daemon()

        self.send_timer = QTimer(singleShot=True, interval=400)
        self.send_timer.timeout.connect(self._flush_send)
        self.server = QLocalServer()
        QLocalServer.removeServer(SERVER_NAME)
        self.server.listen(SERVER_NAME)
        self.server.newConnection.connect(self._on_local)
        if initial_paths:
            self.send_paths(initial_paths)

    # ------------------------------------------------------------ menu
    def _build_menu(self):
        m = self.menu
        m.clear()
        st = self.state.get("settings", {})
        m.addAction("Envoyer un fichier…", self.pick_files)
        m.addAction("Envoyer un dossier…", self.pick_dir)
        n = len(self.incoming)
        if n:
            sub = m.addMenu(f"Réceptions en attente ({n})")
            for x, i in self.incoming.items():
                sub.addAction(f"{i.get('peer_name', '')} → {i['name']} ({human(i.get('size'))})", lambda x=x: self.handle_incoming(x))
        m.addSeparator()
        for label, key in (("Broadcast (visible / recherche)", "broadcast"), ("Échange (réception)", "exchange")):
            a = QAction(label, m, checkable=True)
            a.setChecked(bool(st.get(key)))
            a.setEnabled(bool(st))
            a.triggered.connect(lambda v, k=key: self.ctl.call("set_settings", **{k: v}))
            m.addAction(a)
        z = QAction("Zone de dépôt (glisser-déposer)", m, checkable=True)
        z.setChecked(self.drop.isVisible())
        z.triggered.connect(self.toggle_drop)
        m.addAction(z)
        m.addSeparator()
        m.addAction("Configuration…", self.show_config)
        m.addAction("Quitter tout", self.quit_all)

    def _tray_click(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger and sys.platform != "darwin":
            self.menu.popup(QCursor.pos())
        elif reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_config()

    def toggle_drop(self, on):
        if on:
            geo = self.app.primaryScreen().availableGeometry()
            self.drop.move(geo.right() - 110, geo.bottom() - 130)
            self.drop.show()
        else:
            self.drop.hide()

    def show_config(self):
        self.win.show()
        self.win.raise_()
        self.win.activateWindow()

    def quit_all(self):
        self.ctl.call("quit")
        QTimer.singleShot(300, self.app.quit)

    # ------------------------------------------------------------ daemon state
    def _on_ready(self):
        self.refresh()

    def _on_lost(self):
        self.tray.setIcon(make_icon("#8a8a8a"))
        self.tray.setToolTip("LanShare — service arrêté (reconnexion…)")

    def refresh(self):
        self.ctl.call("state", self._got_state)

    def _got_state(self, m):
        if not m.get("ok"):
            return
        self.state = m["data"]
        self.win.update_state(self.state)
        self.incoming = {i["xfer"]: {**i, "peer_name": self._peer_name(i["peer"])} for i in self.state["incoming"]}
        s = self.state["settings"]
        flags = ("diffusion " if s["broadcast"] else "") + ("échange " if s["exchange"] else "") + ("chiffré" if s["require_encryption"] else "")
        self.tray.setIcon(make_icon("#2b7de9", "#e9a02b" if self.incoming else None))
        self.tray.setToolTip(f"LanShare — {s['name']} [{flags.strip() or 'inactif'}]")
        self._build_menu()

    def _peer_name(self, pid):
        for p in self.state.get("peers", []):
            if p["info"]["id"] == pid:
                return p["info"]["name"]
        return pid[:8]

    # ------------------------------------------------------------ events
    def _notify(self, title, text, action=None):
        self.pending_msg = action
        self.tray.showMessage(title, text, QSystemTrayIcon.MessageIcon.Information, 15000)

    def _msg_clicked(self):
        if self.pending_msg:
            a, self.pending_msg = self.pending_msg, None
            a()

    def _on_event(self, ev):
        k = ev["event"]
        if k in ("state_changed", "paired", "discovered"):
            self.refresh()
        if k == "paired":
            self._notify("LanShare", f"Association réussie avec {ev['info']['name']}")
        elif k == "pair_proposal":
            i = ev["info"]
            self.refresh()
            self._notify("Nouvelle machine", f"{i['name']} cherche des pairs. Cliquez pour l'ajouter.", lambda: self.confirm_pair(i))
        elif k == "pair_request":
            i = ev["info"]
            self.refresh()
            self._notify("Demande d'association", f"{i['name']} veut s'associer. Cliquez pour répondre.", lambda: self.confirm_pair(i))
        elif k == "incoming":
            self.incoming[ev["xfer"]] = ev
            self.win.xfer_event(ev)
            self._build_menu()
            self.tray.setIcon(make_icon("#2b7de9", "#e9a02b"))
            kind = "le dossier" if ev["kind"] == "dir" else "le fichier"
            enc = " 🔒" if ev.get("encrypted") else ""
            self._notify("Réception" + enc, f"{ev['peer_name']} veut envoyer {kind} « {ev['name']} » ({human(ev['size'])}). Cliquez pour choisir la destination.",
                         lambda x=ev["xfer"]: self.handle_incoming(x))
        elif k == "incoming_cancelled":
            self.incoming.pop(ev["xfer"], None)
            self._build_menu()
        elif k in ("xfer_start", "progress"):
            self.win.xfer_event(ev)
        elif k == "xfer_state":
            self.win.xfer_event(ev)
            if ev["state"] in ("retrying", "interrupted") and ev["xfer"] not in self._told:
                self._told.add(ev["xfer"])
                self._notify("Transfert interrompu", "Reprise automatique dès que le pair est de nouveau joignable."
                             if ev["state"] == "retrying" else "Il reprendra à la prochaine connexion de l'expéditeur.")
            elif ev["state"] == "running":
                self._told.discard(ev["xfer"])
        elif k == "done":
            self.win.xfer_event(ev)
            self.incoming.pop(ev["xfer"], None)
            self._build_menu()
            word = "reçu" if ev["dir"] == "in" else "envoyé"
            if ev["ok"]:
                self._notify("Transfert terminé", f"Élément {word} ({human(ev.get('bytes'))}).")
            elif ev.get("error") != "declined":
                self._notify("Transfert échoué", ev.get("error", "erreur inconnue"))
        elif k == "error":
            self._notify("LanShare — erreur", ev["message"])

    def confirm_pair(self, info):
        self.show_config()
        r = QMessageBox.question(
            self.win, "Association",
            f"Associer {peer_label(info)} ?\n\nEmpreinte : {fingerprint(info['id'])}\n"
            "Vérifiez qu'elle est identique sur l'autre machine.")
        if r == QMessageBox.StandardButton.Yes:
            self.win.pair(info["id"])

    # ------------------------------------------------------------ receiving
    def handle_incoming(self, x):
        i = self.incoming.get(x)
        if not i:
            return
        box = QMessageBox(QMessageBox.Icon.Question, "Réception",
                          f"<b>{i.get('peer_name', '')}</b> veut envoyer {'le dossier' if i['kind'] == 'dir' else 'le fichier'} "
                          f"<b>{i['name']}</b> ({human(i.get('size'))}).")
        save, refuse = box.addButton("Enregistrer sous…", QMessageBox.ButtonRole.AcceptRole), box.addButton("Refuser", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton("Plus tard", QMessageBox.ButtonRole.RejectRole)
        box.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
        box.exec()
        if box.clickedButton() is refuse:
            self.ctl.call("reject", xfer=x)
            self.incoming.pop(x, None)
        elif box.clickedButton() is save:
            dl = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation)
            if i["kind"] == "dir":
                dest = QFileDialog.getExistingDirectory(None, f"Dossier où créer « {i['name']} »", dl)
            else:
                dest, _ = QFileDialog.getSaveFileName(None, "Enregistrer sous", str(Path(dl) / i["name"]))
            if dest:
                self.ctl.call("accept", lambda m: m.get("ok") or QMessageBox.warning(None, "Réception", m.get("error", "")), xfer=x, dest=dest)
                self.incoming.pop(x, None)
        self._build_menu()

    # ------------------------------------------------------------ sending
    def pick_files(self):
        paths, _ = QFileDialog.getOpenFileNames(None, "Fichiers à envoyer")
        if paths:
            self.send_paths(paths)

    def pick_dir(self):
        p = QFileDialog.getExistingDirectory(None, "Dossier à envoyer")
        if p:
            self.send_paths([p])

    def send_paths(self, paths):
        """Collect for a moment (Explorer launches one process per selected item), then ask for a recipient."""
        self.buffer.extend(p for p in paths if p not in self.buffer)
        self.send_timer.start()

    def _flush_send(self):
        paths, self.buffer = self.buffer, []
        if not self.ctl.is_ready:
            self.send_timer.start()
            self.buffer = paths
            return
        self.ctl.call("state", lambda m: self._choose(paths, m))

    def _choose(self, paths, m):
        if not m.get("ok"):
            return
        peers = m["data"]["peers"]
        dlg = PeerPicker(peers, paths)
        if dlg.exec() and dlg.chosen():
            self.ctl.call("send", lambda r: r.get("ok") or QMessageBox.warning(None, "Envoi", r.get("error", "")), peer=dlg.chosen(), paths=paths)

    def _on_local(self):
        s = self.server.nextPendingConnection()
        s.waitForReadyRead(500)
        try:
            msg = json.loads(bytes(s.readAll()).decode())
            if msg.get("send"):
                self.send_paths(msg["send"])
            if msg.get("show"):
                self.show_config()
        except ValueError:
            pass
        s.disconnectFromServer()


def forward_to_running(msg: dict) -> bool:
    s = QLocalSocket()
    s.connectToServer(SERVER_NAME)
    if not s.waitForConnected(500):
        return False
    s.write(json.dumps(msg).encode())
    s.waitForBytesWritten(1000)
    s.disconnectFromServer()
    return True


def run(paths=None, cfg=None) -> int:
    app = QApplication(sys.argv[:1])
    app.setQuitOnLastWindowClosed(False)
    app.setApplicationName("LanShare")
    app.setWindowIcon(make_icon())
    if paths and forward_to_running({"send": paths}):
        return 0
    if not paths and forward_to_running({"show": True}):
        return 0
    if not QSystemTrayIcon.isSystemTrayAvailable():
        print("warning: no system tray available; the config window will be shown instead", file=sys.stderr)
    t = TrayApp(app, cfg, paths)
    if not QSystemTrayIcon.isSystemTrayAvailable():
        t.show_config()
    return app.exec()
