"""Fixture preparation and read-back for the healthy-rerun Molecule scenario."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile

import build_container_probe as build
import source_container_probe as source
from state import COMMANDS, RECORD, installation_record


ROOT = Path(__file__).resolve().parent
PREFIX = ROOT / "ruby"
WORKSPACE = ROOT / "absent-workspace"
BASELINE = ROOT / "before.json"
VERSION = "3.4.12"
FLAGS = ("--enable-option-checking=fatal", "--enable-shared", "--enable-rpath",
         "--disable-yjit", "--disable-rjit", "--disable-install-capi", "--disable-install-doc")
RBCONFIG = r'''
require "rbconfig"
c = RbConfig::CONFIG
print [RUBY_VERSION, File.realpath(RbConfig.ruby), c.fetch("prefix"), c.fetch("ENABLE_SHARED"),
       c.fetch("YJIT_SUPPORT"), c.fetch("RJIT_SUPPORT"), c.fetch("configure_args")].join("\0")
'''


def observed_record(prefix, digest):
    result = subprocess.check_output([str(prefix / "bin/ruby"), "--disable=gems,rubyopt", "-e", RBCONFIG],
                                     env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/"},
                                     cwd="/", text=True, timeout=15)
    version, ruby, location, shared, yjit, rjit, args = result.split("\0")
    settings = shlex.split(args)
    if (version != VERSION or Path(ruby) != prefix / "bin/ruby" or Path(location) != prefix
            or (shared, yjit, rjit) != ("yes", "no", "no") or not set(FLAGS).issubset(settings)):
        raise ValueError("built Ruby does not have the expected fixture configuration")
    return installation_record(version, location, digest, shared == "yes",
                               {"yjit": yjit == "yes", "rjit": rjit == "yes"}, "--disable-install-doc" not in settings)


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


def snapshot():
    if os.path.lexists(WORKSPACE):
        raise ValueError("healthy rerun created or used the reserved workspace path")
    packages = subprocess.check_output(["/usr/bin/rpm", "-qa", "--qf",
                                        "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH} %{INSTALLTIME}\n"],
                                       timeout=45).splitlines()
    if not packages:
        raise ValueError("empty fixture RPM inventory")
    return {"prefix": tree_digest(PREFIX), "repository_files": tree_digest(Path("/etc/yum.repos.d")),
            "installed_packages": hashlib.sha256(b"\n".join(sorted(packages))).hexdigest(),
            "public_commands": {cmd: tree_digest(Path("/usr/local/bin") / cmd) for cmd in COMMANDS}}


def build_stage(name, argv, work):
    log = ROOT / (name + ".log")
    with log.open("xb") as handle:
        proc = subprocess.run(argv, cwd=work, stdin=subprocess.DEVNULL, stdout=handle, stderr=subprocess.STDOUT,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(work)})
    if proc.returncode:
        with log.open("rb") as handle:
            handle.seek(max(log.stat().st_size - 8192, 0))
            print(handle.read().decode(errors="replace"), file=sys.stderr)
        raise RuntimeError("fixture " + name + " exited " + str(proc.returncode))


def prepare():
    if (ROOT != Path("/opt/ruby-preflight-healthy") or os.geteuid() != 0 or os.path.lexists(PREFIX)
            or os.path.lexists(WORKSPACE) or os.path.lexists(BASELINE)):
        raise ValueError("fixture preparation requires a fresh scenario directory")
    with tempfile.TemporaryDirectory(prefix="ruby-healthy-") as tmp:
        work = Path(tmp)
        evidence = {}
        archive = build.download(source, work, evidence)
        src = build.extract(source, archive, work / "src", evidence["archive"])
        build_stage("configure", [str(src / "configure"), "--prefix=" + str(PREFIX), *FLAGS], work)
        build_stage("make", ["/usr/bin/make", "-j1"], work)
        build_stage("install", ["/usr/bin/make", "-j1", "install"], work)
    record = observed_record(PREFIX, evidence["sha256"])
    with (PREFIX / RECORD).open("x") as handle:
        json.dump(record, handle, sort_keys=True)
    with BASELINE.open("x") as handle:
        json.dump(snapshot(), handle, sort_keys=True)


def verify():
    expected = json.loads(BASELINE.read_text())
    actual = snapshot()
    changed = [key for key in actual if actual[key] != expected[key]]
    if changed:
        raise ValueError("protected state changed: " + ", ".join(changed))
    print("Managed prefix, public commands, RPM inventory and repository files match; build workspace is absent.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify"))
    if parser.parse_args().action == "prepare":
        prepare()
    else:
        verify()
