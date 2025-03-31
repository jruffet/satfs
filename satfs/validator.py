# SPDX-License-Identifier: MIT

import os
import stat
import fuse
import re
from functools import wraps
from typing import Optional, List, Any, Callable
from .proc import get_init_path
from .satlog import logger, log_level
from .config import config
from .gui import DesktopAdapter

gui = DesktopAdapter()


def append_slash_if_dir(path: str) -> str:
    """Check if directoy and append "/" if it is, so that we can match them in rules"""
    try:
        if path[-1] != "/" and stat.S_ISDIR(os.lstat(f"./{path}").st_mode):
            path = f"{path}/"
    except Exception:
        pass
    return path


class Validator:
    def __init__(
        self,
        path_args_pos: Optional[List[int]] = None,
        path: Optional[str] = None,
        operation: Optional[str] = None,
    ) -> None:
        self.path_args_pos = path_args_pos
        self.path = path
        self.operation = operation

    def __call__(self, decorated_function: Callable) -> Callable:
        @wraps(decorated_function)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not config.fs_init:
                logger.critical("Validator called without fsinit() completed, this should not happen!")
                return -fuse.EPERM

            config.reload_if_needed()

            self.operation = decorated_function.__name__

            logger.debug("")
            logger.debug(f"called: {tuple([self.operation]) + args[1:]}")

            if self.path_args_pos is not None:
                paths = [args[x] for x in self.path_args_pos]
            else:
                paths = [self.path]

            for path in paths:
                ret = self.validate_access(path)
                if ret != 0:
                    return ret

            return decorated_function(*args, **kwargs)

        return wrapper

    def ruling(
        self,
        path: str,
        ret: int,
        msg: str,
        rule: Optional[dict] = None,
        ipn: Optional[str] = None,
        ip: Optional[List[str]] = None,
        silent: bool = False,
    ):
        """Output ruling to logger, and return 'ret'"""
        if not logger.level == log_level("DEBUG"):
            if (
                silent
                or (self.operation == "list_entry" and config.log_level_deny_list_entry < logger.level)
                or (rule is not None and rule["silent"])
            ):
                return ret
        if ret == 0:
            access_str = "GRANTED"
            log_func = logger.info
        else:
            access_str = "DENIED "
            log_func = logger.warn
        ipn_msg = "" if ipn is None else f" ({ipn})"
        ip_msg = "" if ip is None else ip
        rule_msg = ""
        if rule is not None:
            rule_name_msg = ""
            if "name" in rule:
                rule_name = rule["name"]
                rule_name_msg = f" '{rule_name}'"
            pattern_debug_msg = f" -> {rule['pattern']}" if logger.level <= log_level("DEBUG") else ""
            rule_msg = f" in {rule['pattern_type']} rule{rule_name_msg}{pattern_debug_msg}"
        ret_msg = f" ({fuse.errorcode[-ret]})" if (ret != 0 and logger.level <= log_level("WARN")) else ""
        operation_msg = f"({self.operation})"
        if ipn is not None:
            log_func(f"ACCESS {access_str} {operation_msg} {path}{ipn_msg} : {msg}{rule_msg}{ret_msg}")
        else:
            log_func(f"ACCESS {access_str} {operation_msg} {path} : {msg}{rule_msg}{ret_msg} {ip_msg}")
        return ret

    def validate_access(self, path) -> int:
        """
        Validate access for a given path and FUSE context

        Return 0 if OK, negative number with errno otherwise
        """
        # precautionary cleanup
        path = re.sub(r"/+", "/", path)

        fuse_context = fuse.FuseGetContext()
        logger.debug(f"FuseGetContext: {fuse_context}")

        context_pid = fuse_context["pid"]
        context_uid = fuse_context["uid"]

        if context_pid == 0:
            return self.ruling(path=path, ret=0, msg="Operation coming from the kernel (PID 0)")

        if not config.enforce:
            return self.ruling(path=path, ret=0, msg="Enforce is disabled")

        path = append_slash_if_dir(path)

        init_path = get_init_path(pid=context_pid)
        if init_path is None:
            return self.ruling(path=path, ret=config.errno, msg="Could not compute init_path")

        ipn = config.init_path_to_ipn(tuple(init_path), context_uid)

        logger.debug(f"init_path[{context_uid}] ({ipn}): {init_path}")

        ret = None
        silent = False
        is_allowed = False
        reason = None
        for rule_number, rule in enumerate(config.rules):
            if not config.path_in_rule_number(path=path, rule_number=rule_number):
                continue
            # keep errno of the first maching rule
            if ret is None:
                ret = rule["errno"]
            logger.debug(
                f"Found match for {path} (inherit={rule['inherit']}): '{rule['name']}' -> {rule['pattern']}"
            )
            rule_op_ipns = rule["operations"].get(self.operation, [])
            for match_ipn in [ipn, f"ANY[{context_uid}]"]:
                if f"deny:{match_ipn}" in rule_op_ipns:
                    break
                elif f"ignore:{match_ipn}" in rule_op_ipns:
                    silent = True
                    break
                elif f"ask:{match_ipn}" in rule_op_ipns:
                    reason = ""
                    # cache for all operations with "ask:" for the same IPN+PID+path
                    # we don't cache per operation to avoid being bombarded with access requests
                    # ex: file_write is potentially: create -> open_write -> truncate -> chmod
                    key = (match_ipn, context_pid, path)
                    try:
                        is_allowed = config.ask_cache[key]
                        reason = "(cached) "
                    except KeyError:
                        # TODO: create dedicated func to create those strings
                        logger.info(f"ACCESS PENDING ({self.operation}) {path} ({match_ipn})")
                        is_allowed = gui.access_request(
                            ipn=match_ipn,
                            pid=context_pid,
                            operation=self.operation,
                            path=path,
                        )
                        config.ask_cache[key] = is_allowed
                    grant = ["denied", "granted"][is_allowed]
                    reason = f"{reason}access {grant} by user"
                    break
                elif f"allow_silent:{match_ipn}" in rule_op_ipns:
                    silent = True
                    is_allowed = True
                    break
                elif f"allow:{match_ipn}" in rule_op_ipns:
                    is_allowed = True
                    break
            # if we did not break out of previous for loop
            else:
                if rule["inherit"]:
                    continue

            if is_allowed:
                reason = "match" if reason is None else reason
                return self.ruling(
                    path=path, ret=0, ipn=ipn, ip=init_path, rule=rule, msg=reason, silent=silent
                )
            break

        ret = config.errno if ret is None else ret
        reason = "not allowed in any rule" if reason is None else reason

        return self.ruling(path=path, ret=ret, ipn=ipn, ip=init_path, msg=reason, silent=silent)
