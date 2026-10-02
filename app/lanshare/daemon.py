"""Locating, starting and connecting to the Rust daemon (lanshared)."""
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


def config_dir() -> Path:
    """Mirrors dirs::config_dir() + 'lanshare' used by the daemon."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        base = str(Path.home() / "Library" / "Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "lanshare"


def find_binary() -> str | None:
    exe = "lanshared.exe" if sys.platform == "win32" else "lanshared"
    here = Path(__file__).resolve().parent
    candidates = [
        here / "bin" / exe,
        here.parents[1] / "daemon" / "target" / "release" / exe,  # source checkout
        here.parents[1] / "daemon" / "target" / "debug" / exe,
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    return shutil.which(exe)


def read_runtime(cfg: Path | None = None) -> dict | None:
    try:
        return json.loads(((cfg or config_dir()) / "runtime.json").read_text())
    except (OSError, ValueError):
        return None


def spawn(cfg: Path | None = None, extra_args: list[str] | None = None) -> bool:
    """Start the daemon detached from this process. Returns False if no binary."""
    binary = find_binary()
    if not binary:
        return False
    args = [binary] + (["--config-dir", str(cfg)] if cfg else []) + (extra_args or [])
    kw: dict = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if sys.platform == "win32":
        kw["creationflags"] = 0x08000000 | 0x00000008  # CREATE_NO_WINDOW | DETACHED_PROCESS
    else:
        kw["start_new_session"] = True
    subprocess.Popen(args, **kw)
    return True


def wait_runtime(cfg: Path | None = None, timeout: float = 5.0) -> dict | None:
    end = time.time() + timeout
    while time.time() < end:
        rt = read_runtime(cfg)
        if rt:
            return rt
        time.sleep(0.1)
    return None
