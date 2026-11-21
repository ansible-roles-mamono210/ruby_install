"""Snapshot the protected parts of a disposable Molecule target."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_digest(root):
    """Include contents, ownership, permissions, link targets and identity; exclude read access time."""
    if not os.path.lexists(root):
        return None
    digest = hashlib.sha256()

    def visit(path):
        info = path.lstat()
        row = [str(path.relative_to(root)), info.st_mode, info.st_uid, info.st_gid, info.st_dev, info.st_ino,
               info.st_size, info.st_mtime_ns, info.st_ctime_ns]
        if stat.S_ISREG(info.st_mode):
            row.append(file_digest(path))
        elif stat.S_ISLNK(info.st_mode):
            row.append(os.readlink(path))
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError("unexpected file type in fixture snapshot")
        digest.update(json.dumps(row, separators=(",", ":")).encode("ascii") + b"\n")
        if stat.S_ISDIR(info.st_mode):
            for entry in sorted(path.iterdir()):
                visit(entry)

    visit(root)
    return digest.hexdigest()


def snapshot(prefix, commands=None):
    packages = subprocess.check_output(["/usr/bin/rpm", "-qa", "--qf",
                                        "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH} %{INSTALLTIME}\n"],
                                       timeout=45).splitlines()
    if not packages:
        raise ValueError("empty fixture RPM inventory")
    return {"prefix": tree_digest(prefix), "repository_files": tree_digest(Path("/etc/yum.repos.d")),
            "installed_packages": hashlib.sha256(b"\n".join(sorted(packages))).hexdigest(),
            "public_commands": (tree_digest(Path("/usr/local/bin")) if commands is None else
                                {cmd: tree_digest(Path("/usr/local/bin") / cmd) for cmd in commands})}


if __name__ == "__main__":
    print(json.dumps(snapshot(Path(sys.argv[1])), sort_keys=True))
