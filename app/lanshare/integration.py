"""File-manager context-menu entries ("Send with LanShare") for Windows, Linux and macOS.

Everything is installed per user (no admin rights needed).
"""
import os
import shlex
import stat
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

LABEL = "Envoyer avec LanShare"
UID = "lanshare-send-1"


def _python(gui: bool = True) -> str:
    exe = os.path.abspath(sys.executable)
    if sys.platform == "win32" and gui:
        w = Path(exe).with_name("pythonw.exe")
        if w.exists():
            return str(w)
    return exe


def _argv() -> list[str]:
    return [_python(), "-m", "lanshare", "send"]


def _cmd() -> str:
    return " ".join(shlex.quote(a) for a in _argv())


def _write(path: Path, text: str, mode: int | None = None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


# ---------------------------------------------------------------- Windows

def _win(install: bool) -> list[str]:
    import winreg  # type: ignore

    done = []
    # HKCU\Software\Classes is per-user: no elevation required, and merges into HKCR.
    for root in ("*", "Directory"):
        key = rf"Software\Classes\{root}\shell\LanShare"
        if install:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, LABEL)
                winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, _python(False))
                # Explorer starts one process per selected item; the UI merges them into one picker.
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key + r"\command") as k:
                a = _argv()
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, " ".join(f'"{x}"' for x in a) + ' "%1"')
        else:
            for sub in (key + r"\command", key):
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
                except FileNotFoundError:
                    pass
        done.append(f"HKCU\\{key}")
    return done


# ---------------------------------------------------------------- Linux

def _linux(install: bool) -> list[str]:
    home = Path.home()
    data = Path(os.environ.get("XDG_DATA_HOME") or home / ".local" / "share")
    conf = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")
    done = []

    def put(path: Path, text: str, mode=None):
        if install:
            _write(path, text, mode)
        elif path.exists():
            path.unlink()
        done.append(str(path))

    # Nautilus (GNOME Files) scripts
    put(data / "nautilus" / "scripts" / LABEL,
        '#!/bin/bash\nIFS=$\'\\n\' read -r -d \'\' -a files <<< "$NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"\n'
        f'exec {_cmd()} "${{files[@]}}"\n', 0o755)
    # Nemo
    put(data / "nemo" / "actions" / "lanshare.nemo_action",
        f"[Nemo Action]\nName={LABEL}\nComment=Send over the local network\nExec={_cmd()} %F\n"
        "Icon-Name=network-transmit\nSelection=any\nExtensions=any;dir;\n")
    # Dolphin / KDE service menu (Plasma 5 and 6 locations)
    desktop = ("[Desktop Entry]\nType=Service\nMimeType=application/octet-stream;inode/directory;all/all;\n"
               "Actions=lanshare_send\nX-KDE-Priority=TopLevel\n\n[Desktop Action lanshare_send]\n"
               f"Name={LABEL}\nIcon=network-transmit\nExec={_cmd()} %F\n")
    put(data / "kio" / "servicemenus" / "lanshare.desktop", desktop, 0o755)
    put(data / "kservices5" / "ServiceMenus" / "lanshare.desktop", desktop, 0o755)
    # Thunar custom action
    uca = conf / "Thunar" / "uca.xml"
    try:
        tree = ET.parse(uca) if uca.exists() else ET.ElementTree(ET.Element("actions"))
        root = tree.getroot()
        for a in list(root):
            if a.findtext("unique-id") == UID:
                root.remove(a)
        if install:
            a = ET.SubElement(root, "action")
            for tag, val in (("icon", "network-transmit"), ("name", LABEL), ("unique-id", UID),
                             ("command", f"{_cmd()} %F"), ("description", "Send over the local network"),
                             ("patterns", "*")):
                ET.SubElement(a, tag).text = val
            for tag in ("directories", "audio-files", "image-files", "other-files", "text-files", "video-files"):
                ET.SubElement(a, tag)
        uca.parent.mkdir(parents=True, exist_ok=True)
        ET.indent(tree)
        tree.write(uca, encoding="UTF-8", xml_declaration=True)
        done.append(str(uca))
    except ET.ParseError:
        pass
    return done


# ---------------------------------------------------------------- macOS

_WFLOW = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>AMApplicationBuild</key><string>523</string>
<key>AMApplicationVersion</key><string>2.10</string>
<key>AMDocumentVersion</key><string>2</string>
<key>actions</key><array><dict><key>action</key><dict>
<key>AMAccepts</key><dict><key>Container</key><string>List</string><key>Optional</key><true/>
<key>Types</key><array><string>com.apple.cocoa.string</string></array></dict>
<key>AMActionVersion</key><string>2.0.3</string>
<key>AMApplication</key><array><string>Automator</string></array>
<key>AMParameterProperties</key><dict><key>COMMAND_STRING</key><dict/><key>CheckedForUserDefaultShell</key><dict/>
<key>inputMethod</key><dict/><key>shell</key><dict/><key>source</key><dict/></dict>
<key>AMProvides</key><dict><key>Container</key><string>List</string><key>Types</key><array><string>com.apple.cocoa.string</string></array></dict>
<key>ActionBundlePath</key><string>/System/Library/Automator/Run Shell Script.action</string>
<key>ActionName</key><string>Run Shell Script</string>
<key>ActionParameters</key><dict>
<key>COMMAND_STRING</key><string>@COMMAND@</string>
<key>CheckedForUserDefaultShell</key><true/><key>inputMethod</key><integer>1</integer>
<key>shell</key><string>/bin/zsh</string><key>source</key><string></string></dict>
<key>BundleIdentifier</key><string>com.apple.RunShellScript</string>
<key>CFBundleVersion</key><string>2.0.3</string>
<key>Class Name</key><string>RunShellScriptAction</string>
<key>InputUUID</key><string>5A2E2D3C-0E5B-4C61-8D7D-0E5A8E6D1A01</string>
<key>UUID</key><string>7B1C0D2E-6F37-4E4F-9A34-1D1E5C1B2A02</string>
</dict></dict></array>
<key>connectors</key><dict/>
<key>workflowMetaData</key><dict>
<key>serviceInputTypeIdentifier</key><string>com.apple.Automator.fileSystemObject</string>
<key>serviceOutputTypeIdentifier</key><string>com.apple.Automator.nothing</string>
<key>serviceApplicationBundleID</key><string>com.apple.finder</string>
<key>workflowTypeIdentifier</key><string>com.apple.Automator.servicesMenu</string></dict>
</dict></plist>
"""

_INFO = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>NSServices</key><array><dict>
<key>NSMenuItem</key><dict><key>default</key><string>@LABEL@</string></dict>
<key>NSMessage</key><string>runWorkflowAsService</string>
<key>NSRequiredContext</key><dict><key>NSApplicationIdentifier</key><string>com.apple.finder</string></dict>
<key>NSSendFileTypes</key><array><string>public.item</string></array>
</dict></array></dict></plist>
"""


def _mac(install: bool) -> list[str]:
    import shutil
    wf = Path.home() / "Library" / "Services" / f"{LABEL}.workflow"
    if install:
        from xml.sax.saxutils import escape
        _write(wf / "Contents" / "document.wflow", _WFLOW.replace("@COMMAND@", escape(_cmd() + ' "$@"')))
        _write(wf / "Contents" / "Info.plist", _INFO.replace("@LABEL@", LABEL))
    elif wf.exists():
        shutil.rmtree(wf)
    return [str(wf)]


def install(enable: bool = True) -> list[str]:
    if sys.platform == "win32":
        return _win(enable)
    if sys.platform == "darwin":
        return _mac(enable)
    return _linux(enable)
