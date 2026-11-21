"""Observe a matching, trusted installation without using gems or the user's environment."""
import os
import re
import selectors
import shlex
import signal
import stat
import subprocess
import time

from .state import Stop, trusted_dir, trusted_file


def check_runtime_tree(obs, prefix):
    """Check paths Ruby can load from before executing the managed interpreter."""
    libraries = set()
    core_found = False
    for dirname in ("lib", "lib64"):
        lib = prefix / dirname
        if obs.stat(lib) is None:
            continue
        lib, info, _ = obs.resolve(lib)
        if prefix not in lib.parents:
            raise Stop("UNSAFE_PATH: managed library directory resolves outside the prefix")
        trusted_dir(info)
        ruby_dir = lib / "ruby"
        gems = ruby_dir / "gems"
        pending = []
        for entry in lib.iterdir():
            if entry == ruby_dir or ".so" in entry.name:
                pending.append(entry)
        visited = set()
        while pending:
            path = pending.pop()
            resolved, info, _ = obs.resolve(path)
            if lib not in resolved.parents or resolved == gems or gems in resolved.parents:
                raise Stop("UNSAFE_PATH: runtime path leaves the trusted Ruby library tree")
            if stat.S_ISDIR(info.st_mode):
                trusted_dir(info)
                if path == ruby_dir:
                    core_found = True
                if resolved not in visited:
                    visited.add(resolved)
                    # RubyGems is disabled for the probe. User-installed gems and
                    # their generated commands are outside the rerun health check.
                    pending.extend(child for child in resolved.iterdir() if child != gems)
            elif not trusted_file(info):
                raise Stop("UNSAFE_PATH: managed runtime file is not trusted")
            elif path.parent == lib and path.name.startswith("libruby") and ".so" in path.name:
                libraries.add(str(resolved))
    if not core_found or not libraries:
        raise Stop("HEALTH_CHECK_FAILED: managed Ruby code or shared library is missing")
    return libraries


HEADER = r'''
wanted = ARGV.fetch(0)
prefix = ARGV.fetch(1)
if RUBY_VERSION != wanted
  STDOUT.write(["version", RUBY_VERSION].join("\0"))
  exit 0
end
roots = %w[lib/ruby lib64/ruby].map { |p| File.join(prefix, p) }
unless $LOAD_PATH.all? { |p|
    roots.any? { |r| (p == r || p.start_with?(r + "/")) &&
      p != r + "/gems" && !p.start_with?(r + "/gems/") } && p == File.expand_path(p)
  }
  STDOUT.write("load_path")
  exit 0
end
'''

IDENTITY = HEADER + r'''
require "rbconfig"
c = RbConfig::CONFIG
libs = File.foreach("/proc/self/maps").filter_map do |line|
  fields = line.chomp.split(/\s+/, 6)
  path = fields[5]
  next unless path && path.start_with?("/") && File.basename(path).start_with?("libruby")
  File.realpath(path)
end.uniq
names = RUBY_VERSION.start_with?("3.4.") ? %w[YJIT RJIT] : %w[YJIT ZJIT]
jit_running = names.any? do |name|
  RubyVM.const_defined?(name, false) && RubyVM.const_get(name).enabled?
end
STDOUT.write(["identity", File.realpath(RbConfig.ruby), File.realpath(c.fetch("prefix")),
  c.fetch("ENABLE_SHARED"), c.fetch("configure_args"), jit_running.to_s,
  *names.map { |name| c.fetch(name + "_SUPPORT", "") }, *libs].join("\0"))
'''

FEATURES = HEADER + r'''
require "openssl"
require "psych"
require "zlib"
abort unless OpenSSL::Digest.hexdigest("SHA256", "abc") ==
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
abort unless Psych.safe_load("--- 42") == 42 && Zlib.inflate(Zlib.deflate("abc")) == "abc"
STDOUT.write("features")
'''


def bounded_output(argv, timeout=12, limit=64 * 1024, env=None):
    deadline = time.monotonic() + timeout
    error = "HEALTH_CHECK_FAILED: Ruby probe failed, timed out or exceeded its output limit"
    try:
        with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              env=env if env is not None else {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/"}, cwd="/",
                              start_new_session=True) as process:
            try:
                output = bytearray()
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            raise Stop(error)
                        data = os.read(process.stdout.fileno(), min(8192, limit + 1 - len(output)))
                        if not data:
                            break
                        output.extend(data)
                        if len(output) > limit:
                            raise Stop(error)
                # Keep the session leader unreaped until its group is cleaned up.
                # Even a descendant that closed the output pipe cannot outlive the probe.
                while True:
                    status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if status is not None:
                        if status.si_code != os.CLD_EXITED or status.si_status:
                            raise Stop(error)
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise Stop(error)
                    time.sleep(min(0.01, remaining))
                return output.decode("utf-8").split("\0")
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
    except (OSError, UnicodeError) as exc:
        raise Stop(error) from exc


def configurable_flags(argv, wanted):
    # configure_args may contain unrelated toolchain options. For each adopted
    # switch check its last setting, including --enable-x=no forms.
    flags = {}
    for arg in argv:
        for stem, default in (("--enable-", "yes"), ("--disable-", "no")):
            if arg.startswith(stem):
                name, sep, value = arg[len(stem):].partition("=")
                if sep and stem == "--disable-":
                    value = {"yes": "no", "no": "yes"}.get(value, "invalid")
                flags[name] = value if sep else default
    return all(flags.get(name) == value for name, value in wanted.items())


def health_check(obs, prefix, record):
    trusted_libraries = check_runtime_tree(obs, prefix)
    obs.recheck()
    version = record["ruby_version"]
    ruby = prefix / "bin" / "ruby"
    base = [str(ruby), "--disable=gems,rubyopt", "-e"]

    def probe(script):
        fields = bounded_output(base + [script, "--", version, str(prefix)])
        if (len(fields) == 2 and fields[0] == "version" and fields[1] != version
                and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.]+)?", fields[1])):
            raise Stop("VERSION_MISMATCH: running Ruby version differs from the installation record")
        if fields == ["load_path"]:
            raise Stop("BUILD_CONTRACT_MISMATCH: Ruby load path leaves the managed runtime")
        return fields

    fields = probe(IDENTITY)
    if len(fields) < 8 or fields[0] != "identity":
        raise Stop("HEALTH_CHECK_FAILED: invalid response from the Ruby identity probe")
    _, executable, location, shared, arguments, jit_running, yjit_build, other_jit_build, *libraries = fields
    wanted = {"shared": "yes", "rpath": "yes", "option-checking": "fatal", "install-capi": "no",
              "install-doc": "yes" if record["documentation"] else "no"}
    wanted.update({name: "no" for name in record["jit"]})
    if record["documentation"]:
        wanted["install-rdoc"] = "yes"
    try:
        correct_flags = configurable_flags(shlex.split(arguments), wanted)
    except ValueError as exc:
        raise Stop("HEALTH_CHECK_FAILED: Ruby configure arguments cannot be read") from exc
    if (executable != str(ruby) or location != str(prefix) or shared != "yes" or not correct_flags
            or jit_running != "false" or yjit_build not in ("no", "") or other_jit_build not in ("no", "")
            or not libraries or any(path not in trusted_libraries for path in libraries)):
        raise Stop("BUILD_CONTRACT_MISMATCH: running Ruby placement, shared library or build settings differ")
    obs.recheck()
    if probe(FEATURES) != ["features"]:
        raise Stop("HEALTH_CHECK_FAILED: openssl, psych or zlib check failed")
