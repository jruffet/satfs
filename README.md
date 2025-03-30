# SatFS

SatFS is a FUSE-based solution that enforces access control rules to protect a directory and its subtree.
It is mounted on an existing non-empty directory, filtering access to its resources.

It is designed to be very easy to use. The configuration is done via a simple YAML file that defines policies, providing fine-grained control over file access without requiring system-wide modifications.

Access decisions are based on the lineage of the requesting process, tracing its ancestry back to `init`.
The requested path is then matched against the configuration using regex to determine whether the operation is allowed.

Additionally, the system can prompt interactively via a popup, allowing real-time access decisions for greater flexibility.

This project is built on top of [`python-fuse`](https://github.com/libfuse/python-fuse/)

## Limitations

- **Platform:** This is designed to work solely on Linux
- **Performance:** Due to FUSE, Python, and single-threading, this filesystem is pretty slow.
- **Operation Support:** The filesystem supports most standard operations, but some features, such as extended attributes (`xattrs`), are not implemented.
- **Security Considerations:** This filesystem is not a fully secure sandbox by any means. See [Threat Model & Caveats](#threat-model--caveats) for details.


## How It Works
SatFS mounts over an existing directory, acting as a protective layer.

By default, all access is denied.

### Flow overview
When a process accesses a file or directory:
1. SatFS determines the process's *init path* (see below).
2. It checks *rules* to see if the requested operation is allowed, denied, or requires confirmation.
3. If *ask* is set, SatFS prompts the user before proceeding.

**Note:** File operations like `read()` and `write()` on an already open file descriptor are not restricted. SatFS only controls access at the time of opening or performing filesystem operations.

### Process Lineage & Init Path
When a process accesses a file or directory, SatFS traces its parent process chain up to `init` (PID 1). This "init path" is matched against access rules in the configuration.

### Permissions & Operations
Operations (`unlink()`, `mkdir()`, etc.) are grouped into simplified "permissions" for easier rule management.

A `list_entry` operation has been added to allow for hiding files or directories from selected processes.

### Rules & Access Control
Rules define regex-based path matching and specify actions:
- **allow** – Permit access
- **deny** – Block access
- **ask** – Prompt the user interactively via a GTK/QT dialog

### Configuration Auto-Reload
When the configuration file changes (`mtime` update), SatFS reloads it automatically. Since SatFS is single-threaded, no race conditions occur.


## Configuration
See [CONFIG.md](CONFIG.md)

See also [examples](examples/conf)

## How to Use


### Installing SatFS
Clone the repository:

```sh
git clone https://github.com/jruffet/satfs.git
cd satfs
```


You can install dependencies via APT and then install `satfs` without dependencies:

```sh
sudo apt-get install -y python3-fuse python3-prctl python3-yaml python3-systemd
sudo pip install --no-deps .
```
This installs `satfs` as a system-wide Python package and creates the `satfs` executable (typically in `/usr/local/bin/satfs`).

Alternatively deploying `satfs` *with* system-wide dependencies (**not recommended**)
```sh
sudo pip install .
```


### Running SatFS

Before running SatFS, create a system user and group named `satfs`:

    ```sh
    sudo groupadd --system satfs
    sudo useradd --system --gid satfs --shell /usr/sbin/nologin --create-home satfs
    ```

Use the UID and GID of `satfs` (obtain them with `id satfs`) as the values for `dropuid` and `dropgid` when running SatFS.

If `dropuid` and `dropgid` are not provided, SatFS will automatically use the UID/GID of the `satfs` user (which must be a system user with UID/GID less than 1000). Afterward, ensure the configuration file is readbable by the `satfs` user or group.

Run `satfs` in the foreground (with `-f`) or background (without).

Logs go to stderr (if in foreground) and journald. Log level is adjusted in the configuration file.

The filesystem is mounted with the provided `fsuid`/`fsgid` and configuration file.

**Note:** Below example is designed to protect a directory that belongs to user/group `1000/1000`, adjust accordingly.

The following FUSE options are enforced:

- **nonempty:** Because the whole idea is to protect an existing directory.
- **default_permissions:** This ensures that the kernel checks permissions to avoid security risks.
- **use_ino:** Honors the `st_ino` field in kernel functions `getattr()` and `fill_dir()`.
- **allow_other:** Since it effectively runs as the dedicated `satfs` user, this option allows access to the mountpoint.

Consequently, `user_allow_other` must be set in `/etc/fuse.conf`

Example on how to run SatFS:

    ```sh
    sudo satfs -f -o fsuid=1000,fsgid=1000,dropuid=999,dropgid=999,conf=/path/to/your_conf.yml mountpoint
    ```

This command uses FSUID/FSGID `1000/1000` to access `mountpoint` (which should be owned by `1000/1000`) and applies the given configuration.

### Using fstab

To mount via `/etc/fstab`, add the following entry (remove `noauto` if you want to mount SatFS early):

```fstab
none /mountpoint fuse.satfs noauto,fsuid=1000,fsgid=1000,conf=/path/to/your_conf.yml 0 0


In this example, dropuid/dropgid will be UID/GID of the `satfs` system user.

#### Interactive popups (optional)
To enable communication with your desktop environment for interactive popups (see `ask:` in [CONFIG.md](CONFIG.md)), run the following command:

    xhost +SI:localuser:satfs


## Threat Model & Caveats

This filesystem is designed to restrict access to private documents from unauthorized (non-root) applications.
To prevent abuse (e.g., being killed by same UID, non-privileged user), it must be started as root. It drops all capabilities except `CAP_SYS_PTRACE` (`readlink()` to resolve `/proc/PID/exe`). It also drops privileges by setting the RUID/SUID to the provided `dropuid` (or uid of system user "satfs") and the EUID/FSUID to the provided `fsuid` (and similarly for the group IDs).

It should not be considered a bulletproof security solution by any means and has several limitations:

- **Ineffective against root:** A root process can bypass the restrictions entirely, so this filesystem does not protect against privileged attackers.
- **Bypass via `chdir()` before mount:** If a process changes its working directory (`chdir()`) to the mountpoint **before** the filesystem is mounted, it can still access files directly, circumventing the access controls. This can be mitigated by ensuring the filesystem is mounted before starting any user session.
- **/proc/PID/exe abuse:** The satfs code is only triggered when a process tries to access a protected directory. This means that malicious code could `fork()` / `execve()` / etc. beforehand to mimic an authorized "init path". It comes with limitations though, but it is something to keep in mind. This could be mitigated by following execve() calls via e.g. eBPF and/or "registering" apps to satfs.


## Use at Your Own Risk

While it can help restrict unauthorized access to private files, it has inherent limitations (see above).

Users should be aware that:
- This project is provided **as-is**, without guarantees of security or stability.
- Although no file corruption is expected, the author does not guarantee that it is impossible.

**Backup your data!**

Use this project with caution, and do not rely on it for strong security guarantees.
