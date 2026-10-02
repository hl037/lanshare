import argparse
import sys
from pathlib import Path


def main(argv=None):
    ap = argparse.ArgumentParser(prog="lanshare", description="Fast LAN file exchange")
    ap.add_argument("--config-dir", help="daemon config directory (testing)")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("run", help="start the tray application (default)")
    s = sub.add_parser("send", help="send files/folders (used by file-manager context menus)")
    s.add_argument("paths", nargs="+")
    sub.add_parser("install-integration", help="add 'Send with LanShare' to file-manager context menus")
    sub.add_parser("uninstall-integration", help="remove the context-menu entries")
    a = ap.parse_args(argv)

    if a.cmd in ("install-integration", "uninstall-integration"):
        from . import integration
        for p in integration.install(a.cmd == "install-integration"):
            print(p)
        return 0
    from .app import run
    cfg = Path(a.config_dir) if a.config_dir else None
    paths = [str(Path(p).resolve()) for p in a.paths] if a.cmd == "send" else None
    return run(paths, cfg)


if __name__ == "__main__":
    sys.exit(main())
