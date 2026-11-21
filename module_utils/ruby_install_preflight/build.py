"""Install one verified Ruby source into a vacant prefix and commit a verified record."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

from .archive import extract
from .health import bounded_output, health_check
from .state import (COMMANDS, RECORD, SHARED_BASES, Observation, Stop, check_publication,
                    installation_record, jit_settings, overlaps, trusted_dir, trusted_file)


MARKER = ".ruby-install-in-progress"


def check_work(request):
    obs = Observation()
    parent, info, _ = obs.resolve(request["workspace"], sticky=True)
    trusted_dir(info, sticky=True)
    work, info, _ = obs.resolve(request["work"], sticky=True, follow_final=False)
    if (work.parent != parent or not work.name.startswith("ruby-install-") or info is None
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700
            or (info.st_dev, info.st_ino) != (request["work_dev"], request["work_inode"])):
        raise Stop("WORKSPACE_INVALID: private build directory is missing or has changed identity")
    obs.recheck()
    return work


def vacant_prefix(request, work):
    obs = Observation()
    prefix, info, _ = obs.resolve(request["prefix"], missing=True, follow_final=False)
    if str(prefix) in SHARED_BASES or request["prefix"] in SHARED_BASES or overlaps(prefix, work.parent):
        raise Stop("UNSAFE_PATH: a separate dedicated installation prefix is required")
    if info is not None:
        trusted_dir(info)
        if any(prefix.iterdir()):
            raise Stop("INSTALLATION_INCOMPLETE: installation destination became occupied")
    check_publication(obs, prefix, "/usr/local/bin")
    obs.recheck()
    return prefix


@contextmanager
def claim_prefix(prefix):
    prefix.mkdir(mode=0o755, parents=True, exist_ok=True)
    obs = Observation()
    resolved, info, _ = obs.resolve(prefix, follow_final=False)
    trusted_dir(info)
    if resolved != prefix:
        raise Stop("UNSAFE_PATH: installation destination changed")
    directory = os.open(prefix, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not os.path.samestat(info, os.fstat(directory)) or os.listdir(directory):
            raise Stop("INSTALLATION_INCOMPLETE: another installation occupies this prefix")
        marker = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(marker, "wb") as stream:
            # A failed or interrupted install stays visibly incomplete for manual recovery.
            os.fsync(directory)
            obs.recheck()
            yield directory, stream
    finally:
        os.close(directory)


def publish(prefix, directory, stream, record):
    if (not os.path.samestat(os.fstat(directory), os.lstat(prefix))
            or not os.path.samestat(os.fstat(stream.fileno()), os.stat(MARKER, dir_fd=directory, follow_symlinks=False))):
        raise Stop("UNSAFE_PATH: destination changed before record publication")
    stream.write((json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
    stream.flush()
    os.fsync(stream.fileno())
    # A hard link exposes the entire record at once and never replaces an existing entry.
    os.link(MARKER, RECORD, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
    os.unlink(MARKER, dir_fd=directory)
    os.fsync(directory)


GEM_PROBE = r"""
require "rbconfig"
require "rubygems"
require "fiddle"
require "rdoc/ri/paths"
prefix = ARGV.fetch(0)
abort unless Fiddle::SIZEOF_VOIDP > 0
abort unless [Gem.default_dir, Gem::Specification.find_by_name("bundler").full_gem_path].all? { |d|
  File.realpath(d).start_with?(prefix + "/") }
STDOUT.write([RbConfig::CONFIG.fetch("ruby_version"), RDoc::RI::Paths.system_dir].join("\0"))
"""


def verify_installation(prefix, record, env):
    obs = Observation()
    ruby = prefix / "bin" / "ruby"
    for name in COMMANDS:
        command = ruby.parent / name
        resolved, info, _ = obs.resolve(command)
        if (prefix not in resolved.parents or not trusted_file(info) or not info.st_mode & 0o111
                or (name == "ruby" and resolved != ruby)):
            raise Stop("HEALTH_CHECK_FAILED: invalid managed command " + name)
        if name != "ruby":
            with resolved.open("rb") as stream:
                line = stream.readline(512)
            if not re.match(rb"^#!\s*" + re.escape(os.fsencode(ruby)) + rb"(?:\s|$)", line):
                raise Stop("HEALTH_CHECK_FAILED: unexpected interpreter for " + name)
    health_check(obs, prefix, record)
    for name in COMMANDS:
        try:
            output = bounded_output([str(ruby.parent / name), "--version"], env=env)
            if not "".join(output).strip():
                raise Stop("missing command output")
        except Stop as exc:
            raise Stop("HEALTH_CHECK_FAILED: managed command failed: " + name) from exc
    abi, path = bounded_output([str(ruby), "--disable=rubyopt", "-e", GEM_PROBE, "--", str(prefix)], env=env)
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", abi) or path != str(prefix / "share" / "ri" / abi / "system"):
        raise Stop("HEALTH_CHECK_FAILED: unexpected standard documentation path")
    docs, info, _ = obs.resolve(path, missing=True)
    if prefix not in docs.parents:
        raise Stop("HEALTH_CHECK_FAILED: documentation leaves the managed prefix")
    if record["documentation"]:
        data, entry, _ = obs.resolve(docs / "String" / "cdesc-String.ri")
        if docs not in data.parents or not trusted_file(entry):
            raise Stop("HEALTH_CHECK_FAILED: managed String documentation is missing")
        page = bounded_output([str(ruby.parent / "ri"), "--no-pager", "--format=rdoc", "--no-standard-docs",
                               "--doc-dir=" + str(docs), "String"], timeout=30, limit=1024 * 1024, env=env)
        if len(page) != 1 or len(page[0]) < 100 or "String" not in page[0]:
            raise Stop("HEALTH_CHECK_FAILED: managed ri could not read String")
    elif info is not None:
        trusted_dir(info)
        if any(docs.rglob("*.ri")):
            raise Stop("HEALTH_CHECK_FAILED: standard documentation was installed with documentation disabled")
    check_publication(obs, prefix, "/usr/local/bin")
    obs.recheck()


def run_logged(stage, argv, cwd, work, env):
    with (work / (stage + ".log")).open("xb") as log:
        result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise Stop("BUILD_FAILED: see " + stage + ".log")


def install(request, progress):
    work = check_work(request)
    prefix = vacant_prefix(request, work)
    os.umask(0o022)
    for name in ("home", "tmp", "build"):
        (work / name).mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "TMPDIR": str(work / "tmp"),
           "LC_ALL": "C", "TZ": "UTC", "TERM": "dumb"}
    version = request["version"]
    progress["stage"] = "extract"
    source = extract(work, version, request["digest"])
    flags = ["--prefix=" + str(prefix), "--enable-shared", "--enable-rpath", "--enable-option-checking=fatal",
             "--disable-install-capi"] + ["--disable-" + name for name in jit_settings(version)]
    flags.extend(["--enable-install-doc", "--enable-install-rdoc"] if request["documentation"] else ["--disable-install-doc"])
    progress["stage"] = "configure"
    run_logged("configure", [str(source / "configure"), *flags], work / "build", work, env)
    progress["stage"] = "build"
    run_logged("build", ["/usr/bin/make", "-j" + str(request["jobs"])], work / "build", work, env)
    progress["stage"] = "install"
    if vacant_prefix(request, work) != prefix:
        raise Stop("UNSAFE_PATH: installation destination changed during build")
    with claim_prefix(prefix) as (directory, marker):
        run_logged("install", ["/usr/bin/make", "-j1", "install"], work / "build", work, env)
        progress["stage"] = "verify"
        record = installation_record(version, prefix, request["digest"], True, jit_settings(version), request["documentation"])
        verify_installation(prefix, record, dict(env, PATH=str(prefix / "bin") + ":/usr/bin:/bin"))
        progress["stage"] = "record"
        publish(prefix, directory, marker, record)
    progress["stage"] = "cleanup"
    if not request["keep"]:
        work = check_work(request)
        shutil.rmtree(work)
