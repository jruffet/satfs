#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT
#
# Copyright (C) 2025 Jérémy Ruffet <sat@airnux.fr>
#

import os
import pwd
import sys
import fuse
import signal
import time
import satfs.process as process
import satfs.satlog as satlog
from satfs.fuse import SatFS
from satfs.config import config
from satfs.satlog import logger

SATFS_RELEASE = "0.1.1"
MIN_FUSE_VERSION = (0, 2)
MIN_PYTHON_VERSION = (3, 11)


def already_mounted(program_name: str, mountpoint: str) -> bool:
    with open("/proc/mounts", "r") as f:
        return any(line.split()[:3] == [program_name, mountpoint, "fuse"] for line in f)


def fatal_exit(msg) -> None:
    print(f"[FATAL] {msg}", file=sys.stderr)
    sys.exit(1)


def get_system_user_id(name, check_type=None) -> int:
    user_info = pwd.getpwnam(name)
    id_value = user_info.pw_uid if check_type == "uid" else user_info.pw_gid
    assert id_value < 1000
    return id_value


def check_user_allow_other() -> bool:
    fuse_conf_path = "/etc/fuse.conf"

    try:
        with open(fuse_conf_path, "r") as file:
            for line in file:
                if line.strip().startswith("#") or not line.strip():
                    continue  # Skip comments and empty lines
                if "user_allow_other" in line.strip():
                    return True
    except FileNotFoundError:
        fatal_exit(f"{fuse_conf_path} not found")
    return False


def main():
    program_name = "satfs"

    fuse.fuse_python_api = MIN_FUSE_VERSION
    fuse.feature_assert("stateful_files", "has_init")

    server = SatFS(version=f"SatFS {SATFS_RELEASE}", dash_s_do="setsingle")

    server.parser.add_option(mountopt="conf", metavar="CONF_FILE", help="SatFS configuration file")
    server.parser.add_option(mountopt="fsuid", metavar="UID", help="UID to use for the filesystem")
    server.parser.add_option(mountopt="fsgid", metavar="GID", help="GID to use for the filesystem")
    server.parser.add_option(mountopt="dropuid", metavar="UID", help="drop UID (ruid/suid) to this")
    server.parser.add_option(mountopt="dropgid", metavar="UID", help="drop GID (rgid/sgid) to this")
    server.parser.add_option(mountopt="privileged", action="store_true", help="keep CAP_SYS_PTRACE")

    # force mono-threaded for now, fuse.FuseGetContext() is not guaranteed to be accurate otherwise
    server.parser.fuse.multithreaded = False
    server.parse(values=server, errex=1)

    if not hasattr(server, "privileged"):
        server.privileged = False

    # force Fuse options
    for arg in ["nonempty", "allow_other", "default_permissions", "use_ino"]:
        server.fuse_args.optlist.add(arg)

    server.fuse_args.optdict["fsname"] = program_name
    # using subtype makes fuse act as if fsname was not defined for some reason...
    # server.fuse_args.optdict["subtype"] = "satfs"

    try:
        if not hasattr(server, "dropuid"):
            server.dropuid = get_system_user_id("satfs", "uid")
        if not hasattr(server, "dropgid"):
            server.dropgid = get_system_user_id("satfs", "gid")
    except (KeyError, AssertionError):
        fatal_exit("drop uid/gid not provided and no 'satfs' system user/group (ID<1000)")

    if server.fuse_args.mount_expected():
        if sys.version_info < MIN_PYTHON_VERSION:
            fatal_exit(f"SatFS requires Python {'.'.join(str(x) for x in MIN_PYTHON_VERSION)} or higher")
        try:
            assert hasattr(server, "conf"), "Configuration file path must be specified (-o conf)"
            assert hasattr(server, "fsuid"), "FSUID must be specified (-o fsuid)"
            assert hasattr(server, "fsgid"), "FSGID must be specified (-o fsgid)"
            assert int(server.fsuid) != 0, "FSUID must be non-root"
            assert int(server.fsgid) != 0, "FSGID must be non-root"
            assert int(server.dropuid) != 0, "Drop UID must be non-root"
            assert int(server.dropgid) != 0, "Drop GID must be non-root"
            assert check_user_allow_other(), "'user_allow_other' must be set in /etc/fuse.conf"
            assert server.fuse_args.mountpoint is not None, "Mountpoint not provided"
        except AssertionError as e:
            fatal_exit(e)

        process.set_non_dumpable()

        mountpoint = server.fuse_args.mountpoint

        config.set_config_file(server.conf)
        config.fsuid = int(server.fsuid)
        config.fsgid = int(server.fsgid)
        config.dropuid = int(server.dropuid)
        config.dropgid = int(server.dropgid)
        config.mountpoint = mountpoint
        config.privileged = server.privileged
        config.foreground = server.fuse_args.modifiers["foreground"]

        # Ignore SIGINT (KeyboardInterrupt)
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        if already_mounted(program_name, mountpoint):
            fatal_exit(f"{program_name} already mounted on {mountpoint}")
        # hide options from ps
        process.set_proc_title(f"{program_name} {mountpoint}")

        satlog.setup_logger(foreground=config.foreground)

        try:
            config.load()
        except Exception as e:
            fatal_exit(f"Could not load configuration: {e}")

        os.chdir(mountpoint)

        server.child_pid = None
        child_pid = os.fork()
        if child_pid == 0:
            # --- Child Process ---
            # Keep a "reference" to the underlying dir (cwd) until we are killed by parent
            # 5 seconds tops, so that we end up exiting in all cases,
            # even if something went wrong with the parent
            process.set_privileges(
                uid=config.dropuid,
                gid=config.dropgid,
                clear_groups=True,
                caps=[],
            )
            time.sleep(5)
            sys.exit(1)

        # --- Parent Process ---
        # used to kill the child later at fsinit() in Fuse code
        server.child_pid = child_pid
        # use mountpoint in child mnt ns as source
        server.source = f"/proc/{child_pid}/cwd"

        # keep real/saved UID/GID to dropuid/dropgid to prevent other non-priv to umount or SIGKILL us
        process.set_privileges(
            euid=config.fsuid,
            egid=config.fsgid,
            fsuid=config.fsuid,
            fsgid=config.fsgid,
            ruid=config.dropuid,
            rgid=config.dropgid,
            suid=config.dropuid,
            sgid=config.dropgid,
            clear_groups=True,
            # keep CAP_SYS_PTRACE for now to be able to chdir() to the child's cwd in fsinit()
            # we will drop the capability in fsinit(), unless -o privileged
            caps=["CAP_SYS_PTRACE"],
        )

        # pre-flight check
        # the "real" chdir() happens in fsinit() in fuse.py,
        # after we are detached and chdir("/") by FUSE
        try:
            os.chdir(server.source)
        except OSError as e:
            if child_pid is not None:
                os.kill(child_pid, signal.SIGUSR1)
            fatal_exit(f"Can't enter cwd of child: {e}")

        # not quite true yet
        logger.critical("*** SatFS mounted ***")

    server.main()

    if server.fuse_args.mount_expected():
        logger.critical("*** SatFS unmounted ***")


if __name__ == "__main__":
    main()
