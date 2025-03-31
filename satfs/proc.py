# SPDX-License-Identifier: MIT

# this module retrieves process information (way faster than psutil)

import os
from typing import Optional, List
from .satlog import logger
from .config import config


def get_uid_from_proc(pid: int) -> Optional[int]:
    """Return real UID of a process given its PID"""
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[1])  # Real UID is the first value
    except Exception:
        pass
    return None


def get_exe_from_proc(pid: int) -> Optional[str]:
    """
    Return the executable path of a process given its PID

    Depending on config.privileged,
    fall back to /proc/PID/comm if /proc/PID/exe is not readable
    """
    exe_path = f"/proc/{pid}/exe"
    try:
        return os.readlink(exe_path).replace(" (deleted)", "")
    except PermissionError:
        if not config.privileged:
            try:
                uid = get_uid_from_proc(pid)
                if uid is None:
                    return None
                with open(f"/proc/{pid}/comm", "r") as f:
                    comm = f.read().strip()
                    if uid == config.fsuid:
                        return f"comm:{comm}"
                    else:
                        return f"comm[{uid}]:{comm}"

            except Exception:
                pass
    return None


def get_ppid_from_proc(pid: int) -> Optional[int]:
    """Return the parent PID for a given PID"""
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
    """Return the PID lineage up to init for a given PID"""
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
        proc_exe = get_exe_from_proc(pid=cur_pid)
        if proc_exe is None:
            return None
        init_path.append(proc_exe)
    return init_path
