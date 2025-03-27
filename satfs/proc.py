# SPDX-License-Identifier: MIT

# this module retrieves process information (way faster than psutil)

import os
from typing import Optional, List
from .satlog import logger


def get_exe_from_proc(pid: int) -> Optional[str]:
    """Return the executable path of a process given its PID."""
    exe_path = f"/proc/{pid}/exe"
    try:
        # ignore deleted state
        rl = os.readlink(exe_path).replace(" (deleted)", "")
        return rl
    except Exception:
        return None


def get_ppid_from_proc(pid: int) -> Optional[int]:
    """Return the parent PID for a given PID."""
    if pid == 1:
        return None

    stat_path = f"/proc/{pid}/stat"
    try:
        with open(stat_path, "r") as f:
            data = f.read()
            end = data.find(")")
            fields = data[end + 2 :].split()
            ppid = int(fields[1])
            return ppid
    except Exception:
        return None


def get_ppids_from_proc(pid: int) -> Optional[List[int]]:
    parents_pid = []
    while pid and pid != 1:
        ppid = get_ppid_from_proc(pid)
        if ppid is None:
            return None
        parents_pid.append(ppid)
        pid = ppid
    return parents_pid


def get_init_path(pid: int) -> Optional[List[str]]:
    parents = get_ppids_from_proc(pid)
    if parents is None:
        return None
    init_path_pids = parents[::-1][1:] + [pid]
    logger.debug(f"get_init_path: {init_path_pids}")
    init_path = []
    for cur_pid in init_path_pids:
        proc_exe = get_exe_from_proc(cur_pid)
        if proc_exe is None:
            return None
        init_path.append(proc_exe)
    return init_path
