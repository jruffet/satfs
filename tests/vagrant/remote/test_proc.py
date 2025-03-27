# SPDX-License-Identifier: MIT

import os
import psutil
import pytest
from satfs import proc


@pytest.fixture(autouse=True, scope="session")
def setup(request):
    pid = os.getpid()
    psu = psutil.Process(pid)
    return pid, psu


def test_proc_exe(setup):
    pid, psu = setup
    exe = proc.get_exe_from_proc(pid)
    assert exe == psu.exe()


def test_proc_ppid(setup):
    pid, psu = setup
    ppid = proc.get_ppid_from_proc(pid)
    assert ppid == psu.ppid()


def test_proc_ppids(setup):
    pid, psu = setup
    ppids = proc.get_ppids_from_proc(pid)

    psu_ppids = []
    while psu.pid != 1:
        psu = psu.parent()
        psu_ppids.append(psu.pid)
    assert ppids == psu_ppids


def test_get_init_path(setup):
    pid, psu = setup
    init_path = proc.get_init_path(pid)

    psu_init_path = [psu.exe()]
    while psu.pid != 1:
        psu = psu.parent()
        psu_init_path.append(psu.exe())
    # reverse and remove PID 1
    assert init_path == psu_init_path[::-1][1:]
