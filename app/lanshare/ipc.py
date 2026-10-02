"""JSON-lines client for the daemon control channel, on top of QTcpSocket."""
import json
from typing import Callable

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtNetwork import QAbstractSocket, QHostAddress, QTcpSocket

from . import daemon


class DaemonClient(QObject):
    ready = Signal()
    lost = Signal()
    event = Signal(dict)

    def __init__(self, cfg=None, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self._seq = 0
        self._cbs: dict[int, Callable | None] = {}
        self._buf = b""
        self._spawned = False
        self.sock = QTcpSocket(self)
        self.sock.readyRead.connect(self._on_data)
        self.sock.connected.connect(self._on_connected)
        self.sock.disconnected.connect(self._on_lost)
        self.sock.errorOccurred.connect(self._on_error)
        self.is_ready = False
        self._retry = QTimer(self)
        self._retry.setInterval(1000)
        self._retry.timeout.connect(self.connect_daemon)

    def connect_daemon(self):
        if self.sock.state() != QAbstractSocket.SocketState.UnconnectedState:
            return
        rt = daemon.read_runtime(self.cfg)
        if not rt:
            if not self._spawned:
                self._spawned = True
                daemon.spawn(self.cfg)
            self._retry.start()
            return
        self._rt = rt
        self.sock.connectToHost(QHostAddress.SpecialAddress.LocalHost, rt["port"])

    def _on_connected(self):
        self._retry.stop()
        self._write({"cmd": "auth", "token": self._rt["token"], "rid": 0})

    def _on_error(self, _):
        if not self.is_ready:
            # stale runtime.json (daemon died) or not started yet: start one once, then retry
            if self._spawned is False:
                self._spawned = True
                daemon.spawn(self.cfg)
            self._retry.start()

    def _on_lost(self):
        was = self.is_ready
        self.is_ready = False
        self._buf = b""
        for cb in self._cbs.values():
            if cb:
                cb({"ok": False, "error": "daemon disconnected"})
        self._cbs.clear()
        if was:
            self.lost.emit()
        self._retry.start()

    def _write(self, obj):
        self.sock.write((json.dumps(obj) + "\n").encode())

    def call(self, cmd: str, callback: Callable | None = None, **kw):
        self._seq += 1
        self._cbs[self._seq] = callback
        self._write({"cmd": cmd, "rid": self._seq, **kw})

    def _on_data(self):
        self._buf += bytes(self.sock.readAll())
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if "re" in m:
                if m["re"] == 0:
                    self.is_ready = True
                    self.ready.emit()
                    continue
                cb = self._cbs.pop(m["re"], None)
                if cb:
                    cb(m)
            else:
                self.event.emit(m)
