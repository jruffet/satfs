# SPDX-License-Identifier: MIT

import pytest

uid, gid = 1000, 1000
mountpoint = "/mnt/satfs"


@pytest.fixture
def satfs_conf(host):
    hostname = host.backend.get_hostname()
    for distro in ["debian-bookworm", "debian-testing"]:
        if distro in hostname:
            return f"/etc/satfs/vagrant-{distro}.yml"
    pytest.fail(f"Unsupported hostname or path not recognized: {hostname}")


@pytest.fixture
def satfs_cmd(host, satfs_conf):
    return f"/vagrant/main.py -o uid={uid},gid={gid},conf={satfs_conf} {mountpoint}"


@pytest.fixture(autouse=True, scope="function")
def setup_satfs(host, satfs_cmd):
    with host.sudo():
        host.run(f"umount {mountpoint}")
        # cleanup and populate "fake" binaries
        host.run("rm -f /usr/local/bin/fake-*")
        host.run("cp -a /usr/bin/find /usr/local/bin/fake-vlc")
        host.run("cp -a /usr/bin/cat /usr/local/bin/fake-mplayer")
        # cleanup and populate source dir
        host.run(f"rm -rf {mountpoint}/*")
        host.run(f"mkdir {mountpoint}/dir")
        host.run(
            f"""
            for ext in png odt mkv txt; do
                echo bla > {mountpoint}/file.$ext;
                echo blu > {mountpoint}/dir/file.$ext;
            done
            """
        )
        host.run(f"touch {mountpoint}/file_no_ext")
        # deploy config and run
        host.run("rm -rf /etc/satfs && umask 077 && mkdir /etc/satfs")
        host.run("cp -a /vagrant/examples/conf/* /etc/satfs/")
        # cleanup journal for later checks
        host.run("journalctl --rotate --vacuum-time=1s -t satfs")
        # mount satfs
        host.run(satfs_cmd)


def test_capabilities_and_perms(host):
    pid = host.run(f"pgrep -f '^satfs {mountpoint}$'").stdout.strip()
    # verify we have only one PID
    assert pid.isnumeric()

    with host.sudo():
        pid_caps = host.run(f"getpcaps {pid}").stdout
        assert "=p cap_setgid,cap_setuid,cap_sys_ptrace+e" in pid_caps

        pid_status = host.file(f"/proc/{pid}/status").content_string
        # real, effective, saved, FS
        assert "Uid:\t0\t1000\t0\t1000" in pid_status
        assert "Gid:\t0\t1000\t0\t1000" in pid_status


def test_fs_operations(host, satfs_conf):
    # We just want to test the fuse part, so we bypass the access control.
    with host.sudo():
        host.run(f"sed 's/enforce: true/enforce: false/g' -i {satfs_conf}")

    test_file = f"{mountpoint}/testfile.txt"
    test_dir = f"{mountpoint}/testdir"
    symlink_path = f"{mountpoint}/testlink"
    hardlink_path = f"{mountpoint}/testhardlink"
    new_file_path = f"{mountpoint}/testfile_renamed.txt"

    # Create a file
    file = host.file(test_file)
    assert host.run(f"touch {test_file}").rc == 0
    assert file.exists
    assert file.is_file

    # Get filesystem stats (statfs)
    assert host.run(f"stat -f {mountpoint}").rc == 0

    # Readlink (should fail because it's not a symlink)
    assert not file.is_symlink

    # Symlink
    assert host.run(f"ln -s {test_file} {symlink_path}").rc == 0
    symlink = host.file(symlink_path)
    assert symlink.is_symlink
    assert symlink.linked_to == test_file

    # Hardlink
    assert host.run(f"ln {test_file} {hardlink_path}").rc == 0
    hardlink = host.file(hardlink_path)
    assert hardlink.exists
    assert hardlink.is_file
    assert hardlink.inode == file.inode  # Ensure it is a hard link

    # Get attributes
    assert file.size == 0  # Empty file after creation

    # Make directory
    dir = host.file(test_dir)
    assert host.run(f"mkdir {test_dir}").rc == 0
    assert dir.exists
    assert dir.is_directory

    # List directory contents
    assert "testfile.txt" in host.check_output(f"ls {mountpoint}/")

    # Change file mode
    assert host.run(f"chmod 600 {test_file}").rc == 0
    assert file.mode == 0o600

    # Change file ownership
    with host.sudo():
        # we are running with fsuid(1000) and no CAP_CHOWN
        assert host.run(f"chown root:root {test_file}").rc == 1

        assert host.run(f"chown vagrant:vagrant {test_file}").rc == 0
        assert file.user == "vagrant"
        assert file.group == "vagrant"

        assert host.run(f"rm -f {test_file}").rc == 0
        assert host.run(f"touch {test_file}").rc == 0
        assert file.user == "vagrant"
        assert file.group == "vagrant"

    # Truncate file
    assert host.run(f"echo 'hello world' > {test_file}").rc == 0
    assert host.run(f"truncate -s 5 {test_file}").rc == 0
    assert file.content_string == "hello"

    # Open file for writing
    assert host.run(f"echo -n 'write test' > {test_file}").rc == 0
    assert file.exists
    assert file.content_string == "write test"

    # Open file for reading
    read_output = host.check_output(f"cat {test_file}")
    assert read_output == "write test"

    # Truncate file
    assert host.run(f"truncate -s 5 {test_file}").rc == 0
    assert file.content_string == "write"

    # Append to file
    assert host.run(f"echo ' more' >> {test_file}").rc == 0
    assert file.content_string == "write more\n"

    # Rename file
    assert host.run(f"mv {test_file} {new_file_path}").rc == 0
    new_file = host.file(new_file_path)
    assert new_file.exists
    assert not file.exists  # Old path should be gone

    # Access test (should succeed)
    assert host.run(f"test -r {new_file_path}").rc == 0

    # Modify file timestamps (utime)
    assert host.run(f"touch -d '2000-01-01 00:00:00' {new_file_path}").rc == 0
    assert "2000-01-01" in host.check_output(f"stat {new_file_path}")

    # Remove file
    assert host.run(f"rm {new_file_path}").rc == 0
    assert not new_file.exists

    # Remove directory
    assert host.run(f"rmdir {test_dir}").rc == 0
    assert not dir.exists

    # Create a file with a specific umask (e.g., 0777)
    assert host.run(f"umask 0777 && touch {test_file}").rc == 0
    file = host.file(test_file)
    assert file.mode == 0o000  # Ensure the file has no permissions due to umask 0777


def test_list_entries(host):
    # can only see dirs and video files
    assert sorted(host.run(f"fake-vlc {mountpoint}/").stdout.strip().split("\n")) == [
        f"{mountpoint}/",
        f"{mountpoint}/dir",
        f"{mountpoint}/dir/file.mkv",
        f"{mountpoint}/file.mkv",
    ]
    # can only readdir("/"), no list_entry allowed
    assert sorted(host.run(f"ls -a {mountpoint}/").stdout.strip().split("\n")) == [".", ".."]

    with host.sudo():
        # can list all but "file.mkv", not showing because of inherit:false in rule "video files"
        assert sorted(host.run(f"ls {mountpoint}/").stdout.strip().split("\n")) == [
            "dir",
            "file.odt",
            "file.png",
            "file.txt",
            "file_no_ext",
        ]
        # No -EPERM but non existing
        assert "No such file or directory" in host.run("ls {mountpoint}/dir/file.none").stderr


def test_fs_permissions(host):
    assert host.run(f"fake-mplayer {mountpoint}/dir/file.mkv").stdout.strip() == "blu"
    assert "Operation not permitted" in host.run(f"fake-mplayer {mountpoint}/dir/file.txt").stderr
    assert "Operation not permitted" in host.run(f"fake-mplayer {mountpoint}/dir/file.none").stderr
    # errno: EPIPE in first matching rule
    assert "Broken pipe" in host.run(f"cat {mountpoint}/dir/file.png").stderr
    # sh -c: vagrant_dash in config
    # we are allowed by satfs (no -EPERM), but denied by kernel (-EACCES)
    # because of enforced FUSE default_permissions
    assert "Permission denied" in host.run(f"sh -c 'rm -f {mountpoint}/dir/file.txt'").stderr


def test_mount_twice(host, satfs_cmd):
    with host.sudo():
        assert "[FATAL] satfs already mounted" in host.run(satfs_cmd).stderr
