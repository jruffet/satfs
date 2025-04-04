# SPDX-License-Identifier: MIT


def test_pip_install(host):
    satfs_bin = "/usr/local/bin/satfs"

    with host.sudo():
        host.run("mkdir /opt/satfs")
        host.run("rsync -aAXH --delete /vagrant/ /opt/satfs/")
        assert host.run("pip install --break-system-packages --no-deps /opt/satfs/").rc == 0
    assert host.run(f"{satfs_bin} -h").rc == 0

    with host.sudo():
        assert host.run("pip uninstall --break-system-packages -y satfs").rc == 0
    assert not host.file(satfs_bin).exists
