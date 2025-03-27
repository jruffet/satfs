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
    fsuid: Optional[int] = None,
    fsgid: Optional[int] = None,
    caps: Optional[List[str]] = None,
    clear_groups: Optional[int] = None,
) -> None:

    if caps is not None and caps != []:
        prctl.securebits.no_setuid_fixup = True

    if clear_groups is not None:
        os.setgroups([])

    if gid is not None:
        os.setgid(gid)
    if uid is not None:
        os.setuid(uid)

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
