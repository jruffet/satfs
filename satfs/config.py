# SPDX-License-Identifier: MIT

import os
import yaml
import fuse
import re
import pathlib
import copy
from typing import Optional, Tuple, Dict, List
from itertools import chain
from functools import cache
from . import satlog
from .satlog import logger
from .process import set_privileges
from .cache import TTLCache


def preprocess_yaml(filename: str) -> str:
    """Read a YAML file and replace !include directives with actual YAML content."""
    base_dir = os.path.dirname(os.path.abspath(filename))

    with open(filename, "r") as f:
        lines = []
        for line in f:
            if line.strip().startswith("#!include"):
                included_file = line.strip().split(" ", 1)[1]
                included_path = os.path.join(base_dir, included_file)

                if not os.path.exists(included_path):
                    raise FileNotFoundError(f"Included file not found: {included_path}")

                # Ensure the included file is a YAML file
                if not included_path.endswith((".yaml", ".yml")):
                    raise ValueError(f"Invalid file type for inclusion: {included_path}")

                with open(included_path, "r") as inc_f:
                    included_content = inc_f.readlines()

                lines.extend(included_content)
            else:
                lines.append(line)

    return "".join(lines)


def validate_config_section(config_section: Dict) -> None:
    cs = {
        "name": {"restrict": None, "type": str},
        "enforce": {"restrict": None, "type": bool},
        "inherit_rules": {"restrict": None, "type": bool},
        "log_level": {"restrict": satlog.LOG_LEVELS.keys(), "type": str},
        "log_level_deny_list_entry": {"restrict": satlog.LOG_LEVELS.keys(), "type": str},
        "ask_cache_ttl": {"restrict": None, "type": int},
    }

    assert "name" in config_section, "'config' section must be present, with 'name' defined"

    for item in config_section:
        assert item in cs, f"config section '{item}' is not a valid option"
        assert isinstance(
            config_section[item], cs[item]["type"]
        ), f"config section '{item}' should be of type {cs[item]['type']}"
        if cs[item]["restrict"] is not None:
            assert (
                config_section[item] in cs[item]["restrict"]
            ), f"config section '{item}' uses unknown value '{config_section[item]}'"


def validate_init_paths(init_paths: Dict) -> None:
    assert "names" in init_paths, "init_paths should have 'names'"
    for name, ip in init_paths["names"].items():
        assert isinstance(ip, list), f"init_path '{name}' is not a list"
        for i, path in enumerate(ip):
            if path == "***":
                assert i == len(ip) - 1, f"init_path '{name}': '***' can only be used at the end"

    groups = init_paths.get("groups", [])
    for group, names in groups.items():
        for name in names:
            assert name in init_paths["names"], f"'{name}' declared in group '{group}' not in any init path"


def validate_operations(operations: Dict) -> None:
    valid_ops = [
        "access",
        "chmod",
        "chown",
        "create",
        "getattr",
        "link",
        "list_entry",
        "mkdir",
        "mknod",
        "open_read",
        "open_write",
        "readdir",
        "readlink",
        "rename",
        "rmdir",
        "statfs",
        "symlink",
        "truncate",
        "unlink",
        "utime",
    ]
    for op_type, ops in operations.items():
        for op in ops:
            assert op in valid_ops, f"operation '{op}' is not valid"


def validate_perms(perms: Dict, operations: Dict) -> None:
    for perm, op_type_list in perms.items():
        for op_type in op_type_list:
            assert op_type in operations, f"perm '{perm}': '{op_type}' not found in operations"


def validate_rules(rules: List[Dict], perms: Dict, init_paths: Dict) -> None:
    assert rules != {}, "at least one rule needs to be defined"
    for i, rule in enumerate(rules):
        assert "name" in rule, "Rule #{i} does not have a name"
        assert (
            "regex_path" in rule or "path" in rule
        ), f"Rule '{rule['name']}' is missing a section 'regex_path' or 'path'"

        if "regex_ignorecase" in rule:
            assert isinstance(
                rule["regex_ignorecase"], bool
            ), f"Rule '{rule['name']}': regex_ignorecase should be a boolean"

        perms_section = rule.get("perms", {})
        for perm_name, ipns in perms_section.items():
            assert perm_name in perms, f"Invalid perm '{perm_name}': not declared in 'perms' dict"
            for ipn in ipns:
                if ":" in ipn:
                    assert re.fullmatch(
                        r"(allow|allow_silent|ask|deny|ignore):[^:]+", ipn
                    ), f"rule '{rule['name']}' / perm '{perm_name}': action not in (allow|allow_silent|ask|deny|ignore)"
                if "[" in ipn:
                    assert re.fullmatch(
                        r"[^\[\]]+\[\d+\]", ipn
                    ), f"rule '{rule['name']}' / perm '{perm_name}': UID in brackets is not valid"
                # keep only init path name
                pure_ipn = re.sub(r"(.*:|\[.*)", "", ipn)
                if pure_ipn != "ANY":
                    assert pure_ipn in init_paths.get("names", []) or pure_ipn in init_paths.get(
                        "groups", []
                    ), f"rule '{rule['name']}' / perm '{perm_name}': '{pure_ipn}' not in init_paths names"


class Config:
    def __init__(self) -> None:
        self._config = {
            "path": None,
            "mtime": 0,
        }
        self.name = None
        self.enforce = True
        self.inherit_rules = False
        self.log_level = 0
        self.log_level_deny_list_entry = 0
        self.ask_cache = TTLCache()
        self.ask_cache_ttl = 10
        self.errno = -fuse.EPERM

        self.rules = []
        self.init_paths = {}

        # will be set externally
        self.uid = None
        self.gid = None
        self.mountpoint = None

        self.init_paths = {
            "names": {},
            "groups": {},
        }
        self.perm_to_operations = {}
        self.rules = []

    def set_config_file(self, path: str) -> None:
        self._config["path"] = path
        self._config["mtime"] = 0

    def get_config_file_mtime(self) -> Optional[int]:
        if self._config["path"] is not None:
            try:
                set_privileges(fsuid=0, fsgid=0)
                mtime = os.stat(self._config["path"]).st_mtime
                set_privileges(fsuid=self.uid, fsgid=self.gid)
                return mtime
            except:
                raise
        return None

    def need_reload(self) -> bool:
        config_mtime = self.get_config_file_mtime()
        return config_mtime != self._config["mtime"]

    def expand_ipn(self, ipn: str, init_paths: Dict) -> list:
        my_ipn = ipn
        if not re.search(r"\[\d+\]$", ipn):
            my_ipn = f"{my_ipn}[{self.uid}]"
        if not re.search(r"^(allow|allow_silent|ask|deny|ignore):", my_ipn):
            my_ipn = f"allow:{my_ipn}"

        match = re.fullmatch(r"^(allow|allow_silent|ask|deny|ignore):([a-zA-Z0-9_]+)\[(\d+)\]", my_ipn)
        if match:
            access, pure_ipn, uid = match.groups()
            return [f"{access}:{x}[{uid}]" for x in init_paths["groups"].get(pure_ipn, [pure_ipn])]

    def reload_if_needed(self) -> None:
        if self.need_reload():
            try:
                self.load()
            except Exception as e:
                logger.critical(f"ERROR: Config reload fail (rolling back): {type(e).__name__}: {str(e)}")
            else:
                logger.critical("*** Configuration file reloaded ***")

    def load(self) -> None:
        self._config["mtime"] = self.get_config_file_mtime()
        try:
            set_privileges(fsuid=0, fsgid=0)
            preprocessed_content = preprocess_yaml(self._config["path"])
            config_dict = yaml.safe_load(preprocessed_content)
            set_privileges(fsuid=self.uid, fsgid=self.gid)
        except Exception:
            raise

        try:
            validate_config_section(config_section=config_dict.get("config", {}))
            validate_init_paths(init_paths=config_dict.get("init_paths", {}))
            validate_operations(operations=config_dict.get("operations", {}))
            validate_perms(
                perms=config_dict.get("perms", {}),
                operations=config_dict.get("operations", {}),
            )
            validate_rules(
                rules=config_dict.get("rules", {}),
                perms=config_dict.get("perms", {}),
                init_paths=config_dict.get("init_paths", {}),
            )
        except AssertionError as e:
            raise ValueError(e)

        # config_dict["config"]["name"] tested to exist in validate_config_section()
        config_section = config_dict["config"]

        next_self = {}
        # init self attributes
        next_self["name"] = config_section["name"]
        next_self["enforce"] = config_section.get("enforce", True)
        next_self["inherit_rules"] = config_section.get("inherit_rules", True)
        next_self["ask_cache_ttl"] = config_section.get("ask_cache_ttl", 10)
        next_self["errno"] = -fuse.EPERM

        next_self["log_level"] = satlog.log_level(
            config_section.get("log_level", "INFO"),
        )
        next_self["log_level_deny_list_entry"] = satlog.log_level(
            config_section.get("log_level_deny_list_entry", "DEBUG"),
        )

        next_self["init_paths"] = {}
        next_self["init_paths"]["names"] = config_dict.get("init_paths", {}).get("names", {})
        next_self["init_paths"]["groups"] = config_dict.get("init_paths", {}).get("groups", {})

        next_self["perm_to_operations"] = {
            key: set(chain.from_iterable(config_dict["operations"][op] for op in ops))
            for key, ops in config_dict["perms"].items()
        }

        next_self["rules"] = []
        for rule_number, rule in enumerate(config_dict["rules"]):
            config_rule = {}

            config_rule["name"] = rule.get("name", "<unknown>")
            # store actual return code in rule["errno"]
            config_rule["errno"] = int(f"-{getattr(fuse, rule.get('errno', fuse.errorcode[-self.errno]))}")
            config_rule["inherit"] = rule.get("inherit", next_self["inherit_rules"])
            config_rule["silent"] = rule.get("silent", False)

            if "regex_path" in rule:
                config_rule["pattern"] = rule["regex_path"]
                config_rule["pattern_type"] = "regex"
                re_flags = re.IGNORECASE if rule.get("regex_ignorecase", False) else 0
                config_rule["regex"] = re.compile(rule["regex_path"], flags=re_flags)
            else:
                config_rule["pattern"] = rule["path"]
                config_rule["pattern_type"] = "glob"
                config_rule["glob"] = rule["path"]

            config_rule["operations"] = {}
            for perm in rule.get("perms", []):
                ipns = []
                for ipn in rule["perms"][perm]:
                    ipns.extend(self.expand_ipn(ipn, next_self["init_paths"]))
                operations = next_self["perm_to_operations"][perm]
                for op in operations:
                    for ipn in ipns:
                        config_rule["operations"].setdefault(op, set()).add(ipn)
            next_self["rules"].append(config_rule)

        # Only override the attributes that have been added in config_data
        for key, value in copy.deepcopy(next_self).items():
            self.__dict__[key] = value

        satlog.set_config_name(self.name)
        logger.setLevel(self.log_level)
        self.ask_cache.set_ttl(self.ask_cache_ttl)

        self.ask_cache.clear()
        self.path_in_rule_number.cache_clear()
        self.init_path_to_ipn.cache_clear()

    @cache
    def path_in_rule_number(self, path: str, rule_number: int) -> bool:
        rule = self.rules[rule_number]
        return (rule["pattern_type"] == "glob" and pathlib.PurePath(path).match(rule["glob"])) or (
            rule["pattern_type"] == "regex" and bool(re.fullmatch(rule["regex"], path))
        )

    @cache
    def init_path_to_ipn(self, init_path: Tuple, uid: int) -> Optional[str]:
        if init_path is not None:
            for ipn in self.init_paths["names"]:
                config_init_path = self.init_paths["names"][ipn]
                # if not same length, and config_init_path ends with "***"
                # we will consider both at length of config_init_path (see zip)
                if config_init_path[-1] == "***" or len(init_path) == len(config_init_path):
                    compare_len = (
                        len(config_init_path) - 1 if config_init_path[-1] == "***" else len(config_init_path)
                    )
                    if len(init_path) >= compare_len and all(
                        pathlib.PurePath(path).match(rule_path)
                        for path, rule_path in zip(init_path[:compare_len], config_init_path[:compare_len])
                    ):
                        return f"{ipn}[{uid}]"
        return None


config = Config()
