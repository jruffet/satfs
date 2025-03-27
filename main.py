#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT
#
# Copyright (C) 2025 Jérémy Ruffet <sat@airnux.fr>
#

import os
import sys
import fuse
import signal
import time
import satfs.process as process
import satfs.satlog as satlog
from satfs.fuse import SatFS
from satfs.config import config
from satfs.satlog import logger


def already_mounted(program_name: str, mountpoint: str) -> bool:
    with open("/proc/mounts", "r") as f:
        return any(line.split()[:3] == [program_name, mountpoint, "fuse"] for line in f)


def fatal_exit(msg):
    print(f"[FATAL] {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    program_name = "satfs"

    fuse.fuse_python_api = (0, 2)
    fuse.feature_assert("stateful_files", "has_init")

    server = SatFS(version="SatFS 0.1", dash_s_do="setsingle")

    server.parser.add_option(mountopt="conf", metavar="CONF_FILE", help="SatFS configuration file")
    server.parser.add_option(mountopt="fsuid", metavar="UID", help="fsuid to use")
    server.parser.add_option(mountopt="fsgid", metavar="GID", help="fsgid to use")
    # force mono-threaded for now, fuse.FuseGetContext() is not guaranteed to be exact otherwise
    server.parser.fuse.multithreaded = False
    server.parse(values=server, errex=1)

    # force Fuse options
    for arg in ["nonempty", "allow_other", "default_permissions", "use_ino"]:
        server.fuse_args.optlist.add(arg)

    server.fuse_args.optdict["fsname"] = program_name
    # using subtype makes fuse act as if fsname was not defined for some reason...
    # server.fuse_args.optdict["subtype"] = "satfs"

    if server.fuse_args.mount_expected():
        try:
            assert hasattr(server, "conf"), "Configuration file path must be specified"
            assert hasattr(server, "fsuid"), "FSUID must be specified"
            assert hasattr(server, "fsgid"), "FSGID must be specified"
            assert int(server.fsuid) != 0, "FSUID must be non-root"
            assert int(server.fsgid) != 0, "FSGID must be non-root"
        except AssertionError as e:
            fatal_exit(e)

        process.set_non_dumpable()
        # Ignore SIGINT (KeyboardInterrupt)
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        mountpoint = server.fuse_args.mountpoint
        if already_mounted(program_name, mountpoint):
            fatal_exit(f"{program_name} already mounted on {mountpoint}")
        # hide options from ps
        process.set_proc_title(f"{program_name} {mountpoint}")

        satlog.setup_logger(foreground=server.fuse_args.modifiers["foreground"])

        config.set_config_file(server.conf)
        config.uid = int(server.fsuid)
        config.gid = int(server.fsgid)
        config.mountpoint = mountpoint

        try:
            config.load()
        except Exception as e:
            fatal_exit(f"Could not load configuration: {e}")

        server.child_pid = None
        read_fd, write_fd = os.pipe()

        child_pid = os.fork()
        parent_mnt_ns = process.get_current_mnt_ns()
        if child_pid == 0:
            # --- Child Process ---
            os.close(read_fd)
            try:
                # set up mnt ns to keep a reference of source before mount
                # technically, just chdir() would work because we only use relative paths for source
                # but that works only in foreground mode.
                # In background mode we get forked, detached and chdir'ed by Fuse later
                # This code keeps a reference we can later use to chdir() to.
                process.create_mnt_ns()
                assert (
                    parent_mnt_ns != process.get_current_mnt_ns()
                ), "parent mnt ns == child mnt ns, this should not happen!"
                process.make_mount_private("/")
                process.set_privileges(clear_groups=True, caps=[])
                os.write(write_fd, b"OK")
            except Exception as e:
                error_msg = f"Error setting up mount namespace: {e}".encode()
                os.write(write_fd, error_msg)
                os.close(write_fd)
                sys.exit(1)

            os.close(write_fd)
            # Keep the mount namespace open until we are killed by parent
            # 1 min tops, so that we end up exiting in all cases,
            # even if something went wrong with the parent
            time.sleep(60)
            sys.exit(1)
        else:
            # --- Parent Process ---
            os.close(write_fd)
            response = os.read(read_fd, 1024).decode()
            os.close(read_fd)

            if response.strip() != "OK":
                fatal_exit(response)

            # use mountpoint in child mnt ns as source
            server.source = f"/proc/{child_pid}/root/{mountpoint}"
            # used to kill the child later at fsinit() in Fuse code
            server.child_pid = child_pid

        # keep UID/GID 0 to prevent non-priv to umount or SIGKILL us
        # keep CAP_SYS_PTRACE to be able to readlink() all /proc/PID/exe
        # keep CAP_SETUID to be able to setuid()/setfsuid() later on
        process.set_privileges(
            fsuid=config.uid,
            fsgid=config.gid,
            clear_groups=True,
            caps=["CAP_SYS_PTRACE", "CAP_SETUID", "CAP_SETGID"],
        )

        try:
            os.chdir(server.source)
        except OSError as e:
            if child_pid is not None:
                os.kill(child_pid, signal.SIGUSR1)
            fatal_exit(f"Can't enter root of the underlying filesystem: {e}")

        logger.critical("*** SatFS mounted ***")

    server.main()

    if server.fuse_args.mount_expected():
        logger.critical("*** SatFS unmounted ***")


if __name__ == "__main__":
    main()
