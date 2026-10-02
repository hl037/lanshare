"""Headless smoke test of the Qt UI against a real daemon (QT_QPA_PLATFORM=offscreen)."""
import sys
from pathlib import Path
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication
from lanshare.app import TrayApp, make_icon

app = QApplication(sys.argv[:1])
t = TrayApp(app, Path("/tmp/uitest"))
res = {}

def check():
    assert t.ctl.is_ready, "not connected"
    assert t.state["identity"]["id"], t.state
    t.ctl.call("set_settings", lambda m: res.update(set=m), broadcast=True, require_encryption=True)
    QTimer.singleShot(500, check2)

def check2():
    t.refresh()
    QTimer.singleShot(500, finish)

def finish():
    s = t.state["settings"]
    assert s["broadcast"] and s["require_encryption"], s
    assert t.win.c_bcast.isChecked() and t.win.c_enc.isChecked()
    acts = [a.text() for a in t.menu.actions() if a.text()]
    print("menu:", acts)
    assert any("Quitter" in a for a in acts) and any("Configuration" in a for a in acts)
    print("window tabs:", [t.win.tabs.tabText(i) for i in range(t.win.tabs.count())])
    t.quit_all()
    QTimer.singleShot(1000, lambda: (print("UI SMOKE OK"), app.quit()))

QTimer.singleShot(2500, check)
app.exec()
