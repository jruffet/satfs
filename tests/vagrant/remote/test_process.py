# SPDX-License-Identifier: MIT

# unit testing on the vagrant box, because we need to be root
# should be launched as root with "--noconftest -p no:cacheprovider --forked"

import subprocess
import prctl
import os
import pwd
import socket
import pytest
import psutil
from satfs import process


def is_mount_private(target: str) -> bool:
    findmnt = subprocess.run(f"findmnt -n -o PROPAGATION {target}", shell=True, capture_output=True)
    return findmnt.stdout.strip() == b"private"


@pytest.fixture(autouse=True, scope="module")
def require_host():
    # Skip tests unless we are on the expected host
    if not socket.gethostname().startswith("satfs-"):
        pytest.skip("Test only runs on 'satfs-*' host")


def test_mnt_ns():
    # Get the original mount namespace
    orig_mnt_ns = process.get_current_mnt_ns()
    assert orig_mnt_ns > 0, "Original mount namespace should be a positive integer"

    # Unshare to create a new mount namespace
    process.create_mnt_ns()
    new_mnt_ns = process.get_current_mnt_ns()
    assert new_mnt_ns > 0, "New mount namespace should be a positive integer"
    assert new_mnt_ns != orig_mnt_ns, "New mount namespace should differ from the original"

    process.make_mount_private("/")
    assert is_mount_private("/"), "Mount point '/' should be private"


def validate_privileges(ruid, rgid, suid, sgid, euid, egid, fsuid, fsgid, caps):
    pid = os.getpid()
    with open(f"/proc/{pid}/status") as f:
        pid_status = f.readlines()
        # real, effective, saved, FS
        assert f"Uid:\t{ruid}\t{euid}\t{suid}\t{fsuid}\n" in pid_status
        assert f"Gid:\t{rgid}\t{egid}\t{sgid}\t{fsgid}\n" in pid_status

    # Check that we have the caps requested
    lower_caps = [x.lower().replace("cap_", "") for x in caps]
    for cap in lower_caps:
        assert getattr(prctl.cap_effective, cap) is True, f"Capability '{cap}' is not set"

    # Check that we ONLY have the caps requested
    for cap in [x for x in prctl.ALL_CAP_NAMES if x not in lower_caps]:
        assert getattr(prctl.cap_effective, cap) is False, f"Capability '{cap}' should NOT be set"


@pytest.mark.parametrize(
    "dropuid, dropgid, fsuid, fsgid, caps",
    [
        (999, 998, 1000, 1000, ["CAP_SYS_PTRACE"]),
        (123, 345, 567, 789, ["CAP_CHOWN"]),
    ],
)
def test_set_privileges(dropuid, dropgid, fsuid, fsgid, caps):
    process.set_privileges(
        ruid=dropuid,
        rgid=dropgid,
        suid=dropuid,
        sgid=dropgid,
        euid=fsuid,
        egid=fsgid,
        fsuid=fsuid,
        fsgid=fsgid,
        caps=caps,
    )
    validate_privileges(
        ruid=dropuid,
        rgid=dropgid,
        suid=dropuid,
        sgid=dropgid,
        euid=fsuid,
        egid=fsgid,
        fsuid=fsuid,
        fsgid=fsgid,
        caps=caps,
    )


def test_set_privileges_multiple():
    fsuid = pwd.getpwnam("vagrant").pw_uid
    fsgid = pwd.getpwnam("vagrant").pw_gid
    dropuid = pwd.getpwnam("satfs").pw_uid
    dropgid = pwd.getpwnam("satfs").pw_gid
    # privileged mode
    satfs_caps = ["CAP_SYS_PTRACE"]

    # main.py
    process.set_privileges(
        ruid=dropuid,
        rgid=dropgid,
        suid=dropuid,
        sgid=dropgid,
        euid=fsuid,
        egid=fsgid,
        fsuid=fsuid,
        fsgid=fsgid,
        caps=satfs_caps,
        clear_groups=True,
    )
    validate_privileges(
        ruid=dropuid,
        rgid=dropgid,
        suid=dropuid,
        sgid=dropgid,
        euid=fsuid,
        egid=fsgid,
        fsuid=fsuid,
        fsgid=fsgid,
        caps=satfs_caps,
    )

    # config read
    process.set_privileges(fsuid=dropuid, fsgid=dropgid)
    validate_privileges(
        ruid=dropuid,
        rgid=dropgid,
        suid=dropuid,
        sgid=dropgid,
        euid=fsuid,
        egid=fsgid,
        fsuid=dropuid,
        fsgid=dropgid,
        caps=satfs_caps,
    )

    # finished reading config
    process.set_privileges(fsuid=fsuid, fsgid=fsgid)
    validate_privileges(
        ruid=dropuid,
        rgid=dropgid,
        suid=dropuid,
        sgid=dropgid,
        euid=fsuid,
        egid=fsgid,
        fsuid=fsuid,
        fsgid=fsgid,
        caps=satfs_caps,
    )

    # gui interactive dialog (after fork() in satfs)
    process.set_privileges(
        uid=dropuid,
        gid=dropgid,
        caps=[],
    )
    # check forked process
    id = subprocess.run("id", capture_output=True)
    assert id.stdout.strip().decode() == f"uid={dropuid}(satfs) gid={dropgid}(satfs) groups={dropgid}(satfs)"
    validate_privileges(
        ruid=dropuid,
        rgid=dropgid,
        suid=dropuid,
        sgid=dropgid,
        euid=dropuid,
        egid=dropgid,
        fsuid=dropuid,
        fsgid=dropgid,
        caps=[],
    )

    with pytest.raises(PermissionError):
        process.set_privileges(euid=0, egid=0)

    with pytest.raises(PermissionError):
        process.set_privileges(fsuid=666, fsgid=666)


def test_set_dumpable():
    prctl.set_dumpable(True)
    assert prctl.get_dumpable() is True
    process.set_non_dumpable()
    assert prctl.get_dumpable() is False


def test_set_proc_title():
    proc_name = "random proc title"
    process.set_proc_title(proc_name)
    p = psutil.Process(os.getpid())
    assert p.cmdline()[0] == proc_name
