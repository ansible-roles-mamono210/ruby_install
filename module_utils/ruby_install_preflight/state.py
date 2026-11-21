"""Read-only preflight for the managed Ruby prefix on Linux (target Python 3.9+)."""
import errno
import json
import os
from pathlib import Path
import re
import stat


RECORD = ".ruby-install-state.json"
RECORD_LIMIT = 64 * 1024
COMMANDS = ("ruby", "gem", "bundle", "bundler", "irb", "erb", "rdoc", "ri", "rake")
SHARED_BASES = frozenset((
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/media",
    "/mnt", "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp",
    "/usr", "/usr/bin", "/usr/lib", "/usr/lib64", "/usr/local", "/usr/local/bin",
    "/usr/local/lib", "/usr/local/sbin", "/usr/sbin", "/var", "/var/tmp",
))
GIB = 1024 ** 3


class Stop(Exception):
    """A diagnostic safe to include in an Ansible result."""


def identity(info):
    if info is None:
        return None
    key = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    if stat.S_ISDIR(info.st_mode):
        # Unrelated entries may be created in a shared directory during inspection.
        return key
    return key + (info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def lstat(path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def trusted_dir(info, sticky=False):
    if (info is None or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or (info.st_mode & 0o022 and not (sticky and info.st_mode & stat.S_ISVTX))):
        raise Stop("UNSAFE_PATH: a required directory is not trusted")


def trusted_file(info):
    return (info is not None and stat.S_ISREG(info.st_mode)
            and info.st_uid == 0 and not info.st_mode & 0o022)


def overlaps(first, second):
    return os.path.commonpath((first, second)) in (str(first), str(second))


class Observation:
    def __init__(self):
        self.seen = {}

    def stat(self, path):
        info = lstat(path)
        key = identity(info)
        if self.seen.setdefault(path, key) != key:
            raise Stop("UNSAFE_PATH: path identity changed during inspection")
        return info

    def recheck(self):
        for path in self.seen:
            self.stat(path)

    def resolve(self, path, missing=False, sticky=False, follow_final=True, allow_dangling=False):
        """Check each directory before using its entries, including symlink targets."""
        path = Path(path)
        if path.anchor != "/" or ".." in path.parts:
            raise Stop("UNSAFE_PATH: expected a normalized absolute path")
        followed = 0

        def walk(current, parts, missing_ok, follow_last):
            nonlocal followed
            info = self.stat(current)
            for index, part in enumerate(parts):
                trusted_dir(info, sticky)
                if part == "..":
                    current = current.parent
                    info = self.stat(current)
                    continue
                child = current / part
                item = self.stat(child)
                if item is None:
                    if not missing_ok or ".." in parts[index + 1:]:
                        raise Stop("UNSAFE_PATH: a required path or symlink target is missing")
                    return child.joinpath(*parts[index + 1:]), None, current
                if stat.S_ISLNK(item.st_mode):
                    if not follow_last and index == len(parts) - 1:
                        raise Stop("UNSAFE_PATH: the final prefix cannot be a symlink")
                    if info.st_mode & 0o022 and item.st_uid != 0:
                        raise Stop("UNSAFE_PATH: untrusted symlink in a shared directory")
                    followed += 1
                    if followed > 40:
                        raise Stop("UNSAFE_PATH: symlink loop or resolution limit")
                    target = Path(os.readlink(child))
                    start = Path("/") if target.is_absolute() else current
                    target_parts = target.parts[1:] if target.is_absolute() else target.parts
                    current, info, parent = walk(start, target_parts, missing_ok and allow_dangling, True)
                    if info is None:
                        tail = parts[index + 1:]
                        if ".." in tail:
                            raise Stop("UNSAFE_PATH: unresolved parent traversal in a symlink")
                        return current.joinpath(*tail), None, parent
                else:
                    current, info = child, item
            return current, info, current

        return walk(Path("/"), path.parts[1:], missing, follow_final)


def jit_settings(version):
    return {"yjit": False, ("rjit" if version.startswith("3.4.") else "zjit"): False}


def installation_record(version, prefix, digest, shared, jit, documentation):
    """Construct the completed record from verified installation settings or a test fixture."""
    return {"schema_version": 1, "state": "complete", "ruby_version": version,
            "canonical_prefix": str(prefix), "source_sha256": digest, "shared": shared,
            "jit": jit, "documentation": documentation}


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def read_record(path, info):
    error = "INSTALL_RECORD_INVALID: a readable, trusted, complete schema-1 record is required"
    if not trusted_file(info) or not info.st_mode & 0o444:
        raise Stop(error)
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        with os.fdopen(os.open(path, flags), "rb") as stream:
            if identity(os.fstat(stream.fileno())) != identity(info):
                raise Stop("UNSAFE_PATH: installation record changed before reading")
            raw = stream.read(RECORD_LIMIT + 1)
            if identity(os.fstat(stream.fileno())) != identity(info):
                raise Stop("UNSAFE_PATH: installation record changed during reading")
        if len(raw) > RECORD_LIMIT:
            raise Stop(error)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_keys)
        keys = {"schema_version", "state", "ruby_version", "canonical_prefix", "source_sha256",
                "shared", "jit", "documentation"}
        if not isinstance(value, dict) or set(value) != keys:
            raise Stop(error)
        version = value["ruby_version"]
        prefix = value["canonical_prefix"]
        if (type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["state"] != "complete" or not isinstance(version, str)
                or not re.fullmatch(r"(?:3\.4|4\.0)\.(?:0|[1-9][0-9]*)", version)
                or not isinstance(prefix, str) or not prefix.startswith("/") or prefix.startswith("//")
                or not prefix.isprintable() or os.path.normpath(prefix) != prefix
                or not isinstance(value["source_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", value["source_sha256"])
                or type(value["shared"]) is not bool or type(value["documentation"]) is not bool
                or not isinstance(value["jit"], dict) or value["jit"].keys() != jit_settings(version).keys()
                or any(type(flag) is not bool for flag in value["jit"].values())):
            raise Stop(error)
        return value
    except (OSError, ValueError, RecursionError) as exc:
        raise Stop(error) from exc


def new_workspace(obs, workspace, prefix, existing):
    try:
        work, wi, _ = obs.resolve(workspace, sticky=True)
        trusted_dir(wi, sticky=True)
    except Stop as exc:
        raise Stop("WORKSPACE_INVALID: cannot resolve a trusted workspace directory") from exc
    try:
        if overlaps(work, prefix):
            raise Stop("WORKSPACE_INVALID: resolved workspace overlaps the prefix")
        if not os.access(work, os.W_OK | os.X_OK, effective_ids=True):
            raise Stop("WORKSPACE_INVALID: workspace is not writable and searchable")
        work_fs = os.statvfs(work)
        if work_fs.f_flag & os.ST_NOEXEC:
            raise Stop("WORKSPACE_NOEXEC: build workspace is mounted noexec")
        if work_fs.f_flag & os.ST_RDONLY:
            raise Stop("WORKSPACE_INVALID: workspace is read-only")
        pi = obs.stat(existing)
        if not os.access(existing, os.W_OK | os.X_OK, effective_ids=True):
            raise Stop("UNSAFE_PATH: installation destination is not writable and searchable")
        if pi.st_dev != wi.st_dev:
            prefix_fs = os.statvfs(existing)
            if prefix_fs.f_flag & os.ST_RDONLY:
                raise Stop("UNSAFE_PATH: installation destination is read-only")
            if prefix_fs.f_bavail * prefix_fs.f_frsize < GIB // 2:
                raise Stop("INSUFFICIENT_SPACE: installation filesystem needs 512 MiB")
        # Bind mounts may be read-only even when they share the workspace device.
        elif os.statvfs(existing).f_flag & os.ST_RDONLY:
            raise Stop("UNSAFE_PATH: installation destination is read-only")
        if work_fs.f_bavail * work_fs.f_frsize < 2 * GIB:
            raise Stop("INSUFFICIENT_SPACE: build filesystem needs 2 GiB")
    except (OSError, AttributeError) as exc:
        raise Stop("WORKSPACE_INVALID: unable to verify workspace or filesystem capacity") from exc


def check_publication(obs, prefix, public_bin):
    directory, info, _ = obs.resolve(public_bin, missing=True)
    if info is None:
        return
    trusted_dir(info)
    for name in COMMANDS:
        path = directory / name
        item = obs.stat(path)
        if item is None or not stat.S_ISLNK(item.st_mode):
            continue
        try:
            target, target_info, _ = obs.resolve(path, missing=True, allow_dangling=True)
        except (OSError, Stop) as exc:
            raise Stop("LINK_STATE_UNCERTAIN: cannot resolve public command " + name) from exc
        if target == prefix or prefix in target.parents:
            raise Stop("RESIDUAL_LINK: remove the public link to this prefix for " + name)
        if target_info is None:
            raise Stop("LINK_STATE_UNCERTAIN: public command target is missing for " + name)


def inspect(request, health_check, public_bin="/usr/local/bin"):
    obs = Observation()
    try:
        prefix, info, existing = obs.resolve(request["prefix"], missing=True, follow_final=False)
        if str(prefix) in SHARED_BASES or request["prefix"] in SHARED_BASES:
            raise Stop("UNSAFE_PATH: choose a dedicated installation prefix")
        if info is not None:
            trusted_dir(info)
            with os.scandir(prefix) as entries:
                empty = next(entries, None) is None
        else:
            empty = True
        if empty:
            new_workspace(obs, request["workspace"], prefix, existing)
            state = "new_install_allowed"
        else:
            bindir = prefix / "bin"
            bin_info = obs.stat(bindir)
            if bin_info is not None:
                trusted_dir(bin_info)
            ruby = bindir / "ruby"
            binary = obs.stat(ruby) if bin_info is not None else None
            if binary is not None and not trusted_file(binary):
                raise Stop("UNSAFE_PATH: bin/ruby must be a trusted regular file")
            path = prefix / RECORD
            record_stat = obs.stat(path)
            if record_stat is None:
                if binary is not None:
                    raise Stop("INSTALL_RECORD_INVALID: existing Ruby has no installation record")
                raise Stop("INSTALLATION_INCOMPLETE: nonempty prefix has no managed Ruby or record")
            record = read_record(path, record_stat)
            if binary is None or not binary.st_mode & 0o111 or not os.access(ruby, os.X_OK, effective_ids=True):
                raise Stop("INSTALLATION_INCOMPLETE: bin/ruby is missing or not executable")
            version = request["version"]
            if record["ruby_version"] != version:
                raise Stop("VERSION_MISMATCH: recorded Ruby version differs")
            expected = installation_record(version, prefix, request["digest"], True, jit_settings(version),
                                           request["documentation"])
            if record != expected:
                raise Stop("BUILD_CONTRACT_MISMATCH: recorded source, placement or build settings differ")
            obs.recheck()
            health_check(obs, prefix, record)
            state = "installed_healthy"
        check_publication(obs, prefix, public_bin)
        obs.recheck()
        if empty and info is not None:
            with os.scandir(prefix) as entries:
                if next(entries, None) is not None:
                    raise Stop("UNSAFE_PATH: the empty prefix changed during inspection")
        return state
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise Stop("UNSAFE_PATH: symlink loop during inspection") from exc
        raise Stop("UNSAFE_PATH: unable to inspect a required path") from exc
