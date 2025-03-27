# SPDX-License-Identifier: MIT

import pytest


@pytest.fixture(autouse=True, scope="module")
def require_vagrant(request):
    hosts = request.config.getoption("hosts")
    if not hosts or "vagrant-satfs" not in hosts:
        pytest.skip("Skipping vagrant tests: --hosts=vagrant-satfs is required")

    host = request.getfixturevalue("host")
    hostname = host.run("hostname").stdout.strip()
    if hostname != "vagrant-satfs":
        pytest.skip(f"Skipping vagrant tests: remote hostname is not 'vagrant-satfs' (got '{hostname}')")
    user = host.run("whoami").stdout.strip()
    if user != "vagrant":
        pytest.skip(f"Skipping vagrant tests: remote user is not 'vagrant' (got '{user}')")
