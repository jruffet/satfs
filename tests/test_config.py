# SPDX-License-Identifier: MIT

import pytest
import yaml
import fuse
import logging
import pathlib
import time
import re
from unittest import mock
from satfs.config import Config, preprocess_yaml
from satfs import satlog

topdir = pathlib.Path(__file__).parent.parent


@pytest.fixture(params=[f"{topdir}/examples/conf/satfs-vagrant.yml"])
def setup(request):
    conf_path = request.param
    config = Config()
    config.set_config_file(conf_path)
    config.uid = 1001
    config.gid = 1001
    with mock.patch("satfs.config.set_privileges", return_value=0):
        config.load()
    with open(conf_path, "r") as f:
        contents = yaml.safe_load(f)
    return conf_path, contents, config


def test_load_raises(setup):
    _, _, config = setup
    config.uid = 99999

    with pytest.raises(PermissionError):
        config.load()

    config.uid = 1000
    config.set_config_file("")
    with mock.patch("satfs.config.set_privileges", return_value=0):
        with pytest.raises(FileNotFoundError):
            config.load()


def test_config_section(setup):
    path, conf_yml, config = setup
    assert config._config["path"] == path
    assert config.name == conf_yml["config"].get("name", None)
    assert config.enforce == conf_yml["config"].get("enforce", None)
    assert config.inherit_rules == conf_yml["config"].get("inherit_rules", None)
    assert config.log_level == logging.INFO
    assert config.log_level_deny_list_entry == logging.WARNING
    assert config.errno == -fuse.EPERM


def test_log_level(setup):
    _, _, config = setup
    satlog.logger.setLevel("WARN")
    assert satlog.logger.level == logging.WARNING


def test_rules(setup):
    _, _, config = setup
    rule = config.rules[0]
    assert rule["name"] == "video files"
    assert "open_write" not in rule["operations"]
    assert rule["operations"]["open_read"] == {
        f"allow:mplayer[{config.uid}]",
        f"allow:vlc[{config.uid}]",
    }


def test_path_in_rules(setup):
    _, _, config = setup
    assert config.path_in_rule_number("/kikoo/lol/some_file.mkV", 0)
    assert config.path_in_rule_number("/test/some_file.mKv", 3)
    assert not config.path_in_rule_number("/some_file.png", 0)
    assert config.path_in_rule_number("/", 3)
    assert not config.path_in_rule_number("//", 4)


def test_ask_cache(setup):
    _, _, config = setup
    # (match_ipn, context_pid, self.path)
    key = ("random[1234]", "12345", "/somewhere")

    config.ask_cache.set_ttl(0.2)
    config.ask_cache[key] = True
    assert config.ask_cache[key], "ask_cache did not properly register our key/value pair"
    time.sleep(0.2)
    assert key not in config.ask_cache, "ask_cache did not cleanup our key/value after TTL"

    config.ask_cache.set_ttl(10)
    config.ask_cache[key] = True
    assert config.ask_cache[key], "ask_cache did not properly register our key/value pair"
    config.ask_cache.set_ttl(0)
    assert key not in config.ask_cache, "ask_cache did not cleanup our key/value after TTL"


def test_init_path_to_ipn(setup):
    _, _, config = setup
    assert config.init_path_to_ipn(("/usr/sbin/sshd", "/usr/lib/openssh/sshd-session"), config.uid) is None

    base = ("/usr/sbin/sshd", "/usr/lib/openssh/sshd-session", "/usr/lib/openssh/sshd-session")
    assert (
        config.init_path_to_ipn(base + ("/usr/bin/dash", "/usr/bin/kikoo", "/opt/lol"), 1234)
        == "vagrant_dash[1234]"
    ), "could not match *** init path"
    assert (
        config.init_path_to_ipn((base + ("/usr/local/bin/fake-vlc",)), 999) == "vlc[999]"
    ), "could not match simple init path"
    assert (
        config.init_path_to_ipn((base + ("/usr/local/bin/fake-kikoo",)), 999) == "any_fake[999]"
    ), "glob match should not be matching first"


def run_bogus_config_test(setup, sub_from, sub_to, exception_type, error_str):
    path, _, config = setup

    raw_yaml = preprocess_yaml(path)
    modified_yaml = re.sub(sub_from, sub_to, raw_yaml, flags=re.MULTILINE, count=1)

    with mock.patch("satfs.config.set_privileges", return_value=0):
        with mock.patch("satfs.config.preprocess_yaml", return_value=modified_yaml):
            with pytest.raises(exception_type) as exc_info:
                config.load()

    assert error_str in str(exc_info.value)


@pytest.mark.parametrize(
    "sub_from, sub_to, exception_type, error_str",
    [
        pytest.param(
            "mplayer:",
            "bogus:",
            ValueError,
            "'mplayer' declared in group 'media_players' not in any init path",
            id="bad_group",
        ),
        pytest.param(
            "^config:",
            "bogus:",
            ValueError,
            "'config' section must be present",
            id="missing_config_section",
        ),
        pytest.param(
            "^  log",
            "  bogus",
            ValueError,
            "config section 'bogus_level' is not a valid option",
            id="bad_config_section",
        ),
        pytest.param(
            "list_read:",
            "bogus:",
            ValueError,
            "Invalid perm 'list_read': not declared in 'perms' dict",
            id="bad_perm",
        ),
        pytest.param(
            "ANY",
            "bogus",
            ValueError,
            "'bogus' not in init_paths names",
            id="bad_init_path",
        ),
        pytest.param(
            "^  log",
            "bogus",
            yaml.scanner.ScannerError,
            "mapping values are not allowed here",
            id="bad_yaml",
        ),
    ],
)
def test_bogus_config(setup, sub_from, sub_to, exception_type, error_str):
    run_bogus_config_test(setup, sub_from, sub_to, exception_type, error_str)
