# SPDX-License-Identifier: MIT

import os
import subprocess
import signal
from .config import config
from .process import set_privileges


def is_executable(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)


class DesktopAdapter:
    def __init__(self) -> None:
        self.desktop_env = None

    def pre_exec(self) -> None:
        # TODO: put those in config
        os.environ["DISPLAY"] = ":0"
        os.environ["XDG_CURRENT_DESKTOP"] = self.desktop_env
        os.environ["XDG_RUNTIME_DIR"] = f"/run/user/{config.uid}"
        set_privileges(uid=config.uid, gid=config.gid, caps=[], clear_groups=True)
        signal.alarm(config.ask_dialog_timeout)

    def ask_user(self, title: str, msg: str) -> bool:
        kdialog = "/usr/bin/kdialog"
        zenity = "/usr/bin/zenity"

        try:
            if is_executable(kdialog):
                self.desktop_env = "KDE"
                # kdialog supports newlines directly in the message and the title
                result = subprocess.run(
                    [kdialog, "--yesno", msg, "--title", title],
                    preexec_fn=self.pre_exec,
                    capture_output=True,
                )
                return result.returncode == 0

            elif is_executable(zenity):
                self.desktop_env = "GNOME"
                # zenity: newlines work if passed in the text argument and a title
                result = subprocess.run(
                    [zenity, "--question", "--no-wrap", f"--text={msg}", f"--title={title}"],
                    preexec_fn=self.pre_exec,
                    capture_output=True,
                )
                return result.returncode == 0
        except Exception:
            pass
        return False

    def access_request(self, ipn: str, pid: str, operation: str, path: str) -> bool:
        msg = f"""{ipn}
(pid: {pid})

Access request ({operation}) on:
{config.mountpoint}{path}
"""
        return self.ask_user(title="SatFS - Access request", msg=msg)
