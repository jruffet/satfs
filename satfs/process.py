# SPDX-License-Identifier: MIT

import os
import prctl
import ctypes
import errno
from typing import Optional, List

CLONE_NEWNS = 0x00020000  # New mount namespace
MS_REC = 16384
MS_PRIVATE = 262144

libc = ctypes.CDLL("libc.so.6", use_errno=True)


def get_current_mnt_ns() -> int:
    # Skip 'mnt:[' and remove ']'
    return int(os.readlink("/proc/self/ns/mnt").strip("mnt:[]"))


def create_mnt_ns() -> None:
    if libc.unshare(CLONE_NEWNS) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def make_mount_private(target: str) -> None:
    # The mount syscall: mount(source, target, filesystemtype, mountflags, data)
    ret = libc.mount(b"none", target.encode(), None, MS_REC | MS_PRIVATE, None)
    if ret != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))


def set_privileges(
    uid: Optional[int] = None,
    gid: Optional[int] = None,
    ruid: Optional[int] = None,
    rgid: Optional[int] = None,
    suid: Optional[int] = None,
    sgid: Optional[int] = None,
    euid: Optional[int] = None,
    egid: Optional[int] = None,
    fsuid: Optional[int] = None,
    fsgid: Optional[int] = None,
    caps: Optional[List[str]] = None,
    clear_groups: Optional[bool] = None,
) -> None:
    """
    Sets user and group privileges for the current process

    Parameters:
        uid: if provided, sets all user-related IDs (ruid, suid, euid, fsuid) to this value
        gid: if provided, sets all group-related IDs (rgid, sgid, egid, fsgid) to this value
        ruid: real user ID to set
        rgid: real group ID to set
        suid: saved user ID to set
        sgid: saved group ID to set
        euid: effective user ID to set
        egid: effective group ID to set
        fsuid: filesystem user ID to set
        fsgid: filesystem group ID to set
        caps: list of capability names to set in the effective capability set
        clear_groups: if true, clears all supplementary groups
    """

    if uid is not None:
        ruid, suid, euid, fsuid = uid, uid, uid, uid
    if gid is not None:
        rgid, sgid, egid, fsgid = gid, gid, gid, gid

    try:
        prctl.securebits.no_setuid_fixup = True
    except PermissionError:
        pass

    if clear_groups is not None:
        os.setgroups([])

    if egid is not None:
        os.setegid(egid)
    if euid is not None:
        os.seteuid(euid)

    if rgid is not None and sgid is not None:
        os.setresgid(rgid, egid if egid is not None else os.getegid(), sgid)
    elif rgid is not None:
        os.setregid(rgid, os.getegid())

    if ruid is not None and suid is not None:
        os.setresuid(ruid, euid if euid is not None else os.geteuid(), suid)
    elif ruid is not None:
        os.setreuid(ruid, os.geteuid())

    if fsgid is not None:
        libc.setfsgid(fsgid)
        new_fsgid = libc.setfsgid(fsgid)
        err = errno.EPERM if new_fsgid != fsgid else ctypes.get_errno()
        if err:
            raise PermissionError(f"setfsgid: {os.strerror(err)}")

    if fsuid is not None:
        libc.setfsuid(fsuid)
        new_fsuid = libc.setfsuid(fsuid)
        err = errno.EPERM if new_fsuid != fsuid else ctypes.get_errno()
        if err:
            raise PermissionError(f"setfsuid: {os.strerror(err)}")

    if caps is not None:
        caps = set(getattr(prctl, x) for x in caps)
        prctl.cap_effective.limit(*caps)


def set_non_dumpable() -> None:
    prctl.set_dumpable(False)


def set_proc_title(title: str) -> None:
    prctl.set_proctitle(title)
