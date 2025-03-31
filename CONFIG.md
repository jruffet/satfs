# SatFS Configuration

# Overview
This document describes the YAML-based configuration system for the FUSE filesystem. The configuration consists of multiple sections that define global settings, process execution chains, access rules, and permissions.
A configuration file can reference other files using the `#!include` directive.

For example:

```
#!include common/perms.yml
```

This mechanism allows modular configurations by including predefined permission definitions. In our example, the included `perms.yml` is treated as an integral part of the configuration.


# Sections

## Global configuration (`config`)
The `config` section defines general settings.

The following defaults are used if a key is not provided:

- **name** (optional, string): The name of the configuration profile. If not provided, it defaults to the mountpoint.
- **enforce** (optional, boolean, default: `true`): Enforces the specified access rules.
- **inherit_rules** (optional, boolean, default: `true`): Allows rules to be inherited.
- **log_level** (optional, string, default: `"INFO"`): Sets the logging verbosity.
- **log_level_deny_list_entry** (optional, string, default: `"DEBUG"`): Sets the logging level for denied list entries.
- **ask_cache_ttl** (optional, integer, default: `1`): Cache time-to-live for interactive access prompts (in seconds). The cache key used by SatFS is `init path`+`PID`+`path`.
- **ask_dialog_timeout** (optional, integer, default: `10`): Time in seconds before killing the dialog in interactive access prompts.

Example with default values:
```yaml
config:
  name: vagrant
  log_level: INFO
  log_level_deny_list_entry: DEBUG
  enforce: true
  inherit_rules: true
  ask_cache_ttl: 1
  ask_dialog_timeout: 10
```

## Lineage (`init_paths`)
Defines execution chains for processes, tracing the lineage back to init.

## Fields:
- **`names`** (mandatory, dictionary): Maps process names to lists of allowed binary paths.
- **`groups`** (optional, dictionary): Defines reusable groups of process names for use in rules.

## Matching behavior:
Entries in `names` are tried in order, and the first match wins. This means it is better to place more specific rules first and use wildcards at the end.

## Wildcards:
- **Glob Wildcards:**
  - The glob wildcard `*` is allowed.
  - The glob wildcard `**` is not allowed.

`comm:` entries (see below) are not matched against glob wildcards, they need to be a perfect match.

- **Special Wildcard (`***`):**
  - `***` has a special meaning and can only be used at the end. It represents anything (either nothing or any lineage).


## Examples


### satfs non-privileged (default):
```yaml
init_paths:
  names:
    login_bash_any: ['comm[0]:login', '/usr/bin/bash', '***']
    vlc: ['comm:systemd', '/usr/bin/vlc']
    mplayer: ['comm:systemd', '/usr/bin/mplayer']
    opt_stuff_any_bin: ['comm:systemd', '/opt/stuff/bin/*']
  groups:
    media_players:
      - vlc
      - mplayer
```

### satfs launched with `-o privileged`:
```yaml
init_paths:
  names:
    login_bash_any: ['/usr/bin/login', '/usr/bin/bash', '***']
    vlc: ['/usr/lib/systemd/systemd', '/usr/bin/vlc']
    mplayer: ['/usr/lib/systemd/systemd', '/usr/bin/mplayer']
    opt_stuff_any_bin: ['/usr/lib/systemd/systemd', '/opt/stuff/bin/*']
  groups:
    media_players:
      - vlc
      - mplayer
```



The `comm:*` entries appear in non-privileged mode (default) when the system fails to read the executable path via `/proc/PID/exe` (using `readlink`) and instead falls back to reading the process name from `/proc/PID/comm`.

For example, in `comm[0]:login`, the `[0]` indicates that the process's UID is `0`, meaning the UID from `/proc/PID/comm` differs from the provided FSUID.

In a privileged setup (which uses `CAP_SYS_PTRACE`), the executable path is always accessible via `/proc/PID/exe`, so you would never use a `comm:*` entry.

To get those entries, you can look at the logs (`journalctl -t satfs`)


## Rules (`rules`)
Defines access control rules based on file paths.

## Fields:
- **name** (mandatory, string): Unique identifier for the rule.
- **path** (optional, string): If provided, used as a glob match.
- **regex_path** (optional, string): A regular expression for matching paths.
- **regex_ignorecase** (optional, boolean, default: `false`): When `true`, regex matching is case-insensitive.
- **perms** (mandatory, dictionary): Specifies the permission sets to apply when the rule matches.
- **inherit** (optional, boolean, default: `true`): When set to `false`, no further rules are processed after a match.
- **errno** (optional, integer): Error code returned when access is denied. The first matching rule with an `errno` applies.

`path`/`regex_path` start from the provided mountpoint. So if satfs is mounted over `/some/example`, then `/` in the config is `/some/example`.

For each entry in `init_paths` or a group (e.g., `media_players`), if no additional permission action is specified, it is implicitly interpreted as:

```
allow:<init_path_or_group>[UID]
```

where `UID` is the FSUID provided in the configuration when starting the filesystem.

In permission rules, the special keyword **ANY** can be used. **ANY** represents any valid init_path, including those that are not explicitly defined in the configuration. For example, using `ANY` or `ANY[0]` grants permission based on any process execution chain, with the `[0]` indicating any process owned by root (UID 0).

The following actions can be specified in permission rules:
- **allow**: Grants access and logs the action.
- **allow_silent**: Grants access without logging.
- **ask**: Interactively asks for permission (via `kdialog` or `zenity`). Answer is cached for `ask_cache_ttl` seconds.
- **deny**: Denies access and logs the denial (if log level is WARN or above)
- **ignore**: Denies access without logging.

## Example:
```yaml
rules:
  - name: video files
    regex_path: .*\.(mp4|mkv|avi)$
    regex_ignorecase: true
    perms:
      list_read:
        - media_players

  - name: mountpoint
    path: /
    perms:
      list: ['ANY', 'ANY[0]']
```

With satfs, you have to explicitely grant operation `list_entry` to a file/dir for it to be listed, so unless you belong to `media_players`, the last bit will list an empty directory (`.` and `..`) for the mountpoint, because `list` is only granted on `/` here.

# Permissions and Operations

## Meta-Operations (`perms`)
Meta-operations (or abstract permission sets) group lower-level operations into higher-level permission definitions. These permission sets are referenced in the rules section to specify what actions are allowed, denied, or require further handling. Their arrangement can be customized to suit your needs.

Below is an example:

```yaml
perms:
  stat: [stat]
  list: [stat, list]
  read: [stat, file_read]

  file_read: [file_read]
  file_write: [file_write]
  file_read_write: [file_read, file_write]

  list_read: [stat, list, file_read]
  all: [stat, list, file_read, file_write, dir_write, metadata_write]
```

## FUSE Operations (`operations`)
FUSE operations define the concrete system calls and actions that the filesystem supports. These definitions are used by the meta-operations in the `perms` section. In other words, the meta-operations map to one or more FUSE operations, allowing you to group and manage them at a higher level. Their arrangement is also customizable.

For example:

```yaml
operations:
  stat: [access, getattr, statfs]
  list: [readdir, list_entry, readlink]
  file_read: [open_read]
  file_write: [open_write, truncate, unlink, create]
  dir_write: [rmdir, mkdir, link, rename, symlink, mknod]
  metadata_write: [chmod, chown, utime]
```

# Rule processing order
1. Rules are evaluated sequentially.
2. If a rule with `inherit: false` matches, no further rules are processed.
3. The first matching rule with an `errno` value determines the error code for denied access.
4. Permissions from matching rules are merged unless a rule stops processing via `inherit: false`.

# Example workflow
1. A process running under `/usr/bin/dash` attempts to list a directory.
2. Its execution chain is verified against the defined `init_paths`.
3. The directory path is matched against the `rules`.
4. If a matching rule grants the required permission (e.g., `list`), access is allowed; otherwise, the first matching `errno` is returned.

---

This concludes the documentation. Adjust the `perms` and `operations` sections as needed since their arrangement is fully customizable.
