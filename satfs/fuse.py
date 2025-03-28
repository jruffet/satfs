# SPDX-License-Identifier: LGPL-2.1
#
# Fuse part based on the work of:
#   Jeff Epler  <jepler@gmail.com>
#   Csaba Henk  <csaba.henk@creo.hu>
#
# Namely: https://github.com/libfuse/python-fuse/blob/v1.0.9/example/xmp.py
# Licensed under the LGPL-2.1
#
# See the LICENSE file for the full project license

from __future__ import annotations
import os
import fcntl
import struct
import signal
import fuse
from fuse import Fuse
from typing import Optional, Generator, Tuple, Any
from .validator import Validator


def flags_to_mode(flags: int) -> str:
    modes_dict = {os.O_RDONLY: "rb", os.O_WRONLY: "wb", os.O_RDWR: "wb+"}
    modes = modes_dict[flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)]
    if flags & os.O_APPEND:
        modes = modes.replace("w", "a", 1)
    return modes


class SatFS(Fuse):
    validator_list_entry = Validator(operation="list_entry")

    def main(self, *a: Any, **kw: Any) -> int:
        self.file_class = self.SatFSFile
        return Fuse.main(self, *a, **kw)

    def fsinit(self) -> None:
        # chdir() "under" the mounted dir
        os.chdir(self.source)
        # no need for the child to hold the reference anymore
        if self.child_pid is not None:
            os.kill(self.child_pid, signal.SIGUSR1)
            os.waitpid(self.child_pid, 0)

    @Validator(path_args_pos=[1])
    def readlink(self, path: str) -> str:
        return os.readlink(f".{path}")

    @Validator(path_args_pos=[1])
    def getattr(self, path: str) -> os.stat_result:
        return os.lstat(f".{path}")

    @Validator(path_args_pos=[1])
    def readdir(self, path: str, offset: int) -> Generator[fuse.Direntry, None, None]:
        yield fuse.Direntry(".")
        yield fuse.Direntry("..")

        for e in os.listdir(f".{path}"):
            if self.validator_list_entry.validate_access(path=f"{path}/{e}") == 0:
                yield fuse.Direntry(e, ino=os.lstat(f".{path}/{e}").st_ino)

    @Validator(path_args_pos=[1])
    def access(self, path: str, mode: int) -> Optional[int]:
        if not os.access(f".{path}", mode):
            return -fuse.EACCES
        return None

    @Validator(path_args_pos=[1])
    def unlink(self, path: str) -> None:
        os.unlink(f".{path}")

    @Validator(path_args_pos=[1])
    def rmdir(self, path: str) -> None:
        os.rmdir(f".{path}")

    @Validator(path_args_pos=[2])
    def symlink(self, path: str, dest: str) -> None:
        os.symlink(path, f".{dest}")

    @Validator(path_args_pos=[1, 2])
    def rename(self, path: str, dest: str) -> None:
        os.rename(f".{path}", f".{dest}")

    @Validator(path_args_pos=[1, 2])
    def link(self, path: str, dest: str) -> None:
        os.link(f".{path}", f".{dest}")

    @Validator(path_args_pos=[1])
    def chmod(self, path: str, mode: int) -> None:
        os.chmod(f".{path}", mode)

    @Validator(path_args_pos=[1])
    def chown(self, path: str, user: int, group: int) -> None:
        os.chown(f".{path}", user, group)

    @Validator(path_args_pos=[1])
    def truncate(self, path: str, len: int) -> None:
        with open(f".{path}", "a") as f:
            f.truncate(len)

    @Validator(path_args_pos=[1])
    def mknod(self, path: str, mode: int, dev: int) -> None:
        os.mknod(f".{path}", mode, dev)

    @Validator(path_args_pos=[1])
    def mkdir(self, path: str, mode: int) -> None:
        os.mkdir(f".{path}", mode)

    @Validator(path_args_pos=[1])
    def utime(self, path: str, times: Optional[Tuple[int, int]]) -> None:
        os.utime(f".{path}", times)

    @Validator(path="/")
    def statfs(self) -> os.statvfs_result:
        return os.statvfs(".")

    @Validator(path_args_pos=[1])
    def open_read(self, path: str, flags: int) -> SatFSFile:
        return self.SatFSFile(path, flags)

    @Validator(path_args_pos=[1])
    def open_write(self, path: str, flags: int) -> SatFSFile:
        return self.SatFSFile(path, flags)

    def open(self, path: str, flags: int) -> SatFSFile:
        modes = flags_to_mode(flags)
        if "a" in modes or "w" in modes:
            return self.open_write(path, flags)
        else:
            return self.open_read(path, flags)

    @Validator(path_args_pos=[1])
    def create(self, path: str, flags: int, mode: int) -> SatFSFile:
        return self.SatFSFile(path, flags, mode)

    class SatFSFile:
        def __init__(self, path: str, flags: int, *mode: int) -> None:
            self.file = os.fdopen(os.open(f".{path}", flags, *mode), flags_to_mode(flags))
            self.fd = self.file.fileno()

        def read(self, length: int, offset: int) -> bytes:
            return os.pread(self.fd, length, offset)

        def write(self, buf: bytes, offset: int) -> int:
            return os.pwrite(self.fd, buf, offset)

        def _fflush(self) -> None:
            if "w" in self.file.mode or "a" in self.file.mode:
                self.file.flush()

        def release(self, flags: int) -> None:
            self.file.close()

        def fsync(self, isfsyncfile: int) -> None:
            self._fflush()
            if isfsyncfile and hasattr(os, "fdatasync"):
                os.fdatasync(self.fd)
            else:
                os.fsync(self.fd)

        def flush(self) -> None:
            self._fflush()
            os.close(os.dup(self.fd))

        def fgetattr(self) -> os.stat_result:
            return os.fstat(self.fd)

        def ftruncate(self, len: int) -> None:
            self.file.truncate(len)

        def lock(self, cmd: int, owner: int, **kw: Any) -> None:
            # Code and comments from https://github.com/libfuse/python-fuse/blob/v1.0.9/example/xmp.py

            # The code here is much rather just a demonstration of the locking
            # API than something which actually was seen to be useful.

            # Advisory file locking is pretty messy in Unix, and the Python
            # interface to this doesn't make it better.
            # We can"t do fcntl(2)/F_GETLK from Python in a platfrom independent
            # way. The following implementation *might* work under Linux.
            #
            if cmd == fcntl.F_GETLK:
                lockdata = struct.pack(
                    "hhQQi", kw["l_type"], os.SEEK_SET, kw["l_start"], kw["l_len"], kw["l_pid"]
                )
                ld2 = fcntl.fcntl(self.fd, fcntl.F_GETLK, lockdata)
                flockfields = ("l_type", "l_whence", "l_start", "l_len", "l_pid")
                uld2 = struct.unpack("hhQQi", ld2)
                res = {}
                for i in range(len(uld2)):
                    res[flockfields[i]] = uld2[i]

                return fuse.Flock(**res)

            # Convert fcntl-ish lock parameters to Python"s weird
            # lockf(3)/flock(2) medley locking API...
            op = {
                fcntl.F_UNLCK: fcntl.LOCK_UN,
                fcntl.F_RDLCK: fcntl.LOCK_SH,
                fcntl.F_WRLCK: fcntl.LOCK_EX,
            }[kw["l_type"]]
            if cmd == fcntl.F_SETLK:
                if op != fcntl.LOCK_UN:
                    op |= fcntl.LOCK_NB
            elif cmd == fcntl.F_SETLKW:
                pass
            else:
                return -fuse.EINVAL

            fcntl.lockf(self.fd, op, kw["l_start"], kw["l_len"])
