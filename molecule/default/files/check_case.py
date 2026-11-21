"""Independent target observations for the six supported release conditions (Python 3.9)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def output(argv, env, stdin=None, stderr=None):
    return subprocess.run(argv, env=env, input=stdin, text=True, stdout=subprocess.PIPE, stderr=stderr,
                          check=True, cwd="/", timeout=60).stdout.strip()


def rust(profile, work, env):
    package = subprocess.run(["/usr/bin/rpm", "-q", "--quiet", "rust"], env=env, check=False).returncode
    path = shutil.which("rustc", path=env["PATH"])
    if profile != "rust":
        require(package == 1 and path is None, "Rust must be absent")
        return {"installed": False}
    require(package == 0 and path is not None, "Rust must be present")
    version = output([path, "--version", "--verbose"], env)
    require(re.search(r"^host: x86_64-unknown-linux-gnu$", version, re.M), "unexpected Rust host")
    obj = work / "probe.o"
    output([path, "--crate-name", "probe", "--crate-type=lib", "--emit=obj", "-o", str(obj), "-"],
           env, "pub fn value() -> u32 { 42 }\n")
    with obj.open("rb") as stream:
        require(stream.read(4) == b"\x7fELF", "compiler did not generate an ELF object")
    return {"installed": True, "path": os.path.realpath(path), "version": version, "compiled_elf_object": True}


RUNTIME = r'''
require "json"; require "rbconfig"; require "openssl"; require "psych"
require "fiddle"; require "zlib"; require "rubygems"; require "rdoc/ri/paths"
c = RbConfig::CONFIG
jits = RUBY_VERSION.start_with?("3.4.") ? %w[YJIT RJIT] : %w[YJIT ZJIT]
libs = File.foreach("/proc/self/maps").filter_map { |line|
  path = line.chomp.split(/\s+/, 6)[5]
  File.realpath(path) if path && File.basename(path).start_with?("libruby") }.uniq
puts JSON.generate(version: RUBY_VERSION, ruby: File.realpath(RbConfig.ruby), prefix: c.fetch("prefix"),
  shared: c.fetch("ENABLE_SHARED"), libraries: libs, flags: c.fetch("configure_args"),
  jit_build: jits.to_h { |j| [j, c[j + "_SUPPORT"]] },
  jit_enabled: jits.to_h { |j| [j, RubyVM.const_defined?(j, false) && RubyVM.const_get(j).enabled?] },
  docs: RDoc::RI::Paths.system_dir, abi: c.fetch("ruby_version"), gem_dir: File.realpath(Gem.default_dir),
  native_ok: Fiddle::SIZEOF_VOIDP > 0 && Psych.safe_load("--- 42") == 42 &&
    Zlib.inflate(Zlib.deflate("ruby")) == "ruby" && OpenSSL::Digest.hexdigest("SHA256", "abc") ==
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
'''


def ruby(version, prefix, profile, env):
    bindir = prefix / "bin"
    env = dict(env, PATH=str(bindir) + ":" + env["PATH"])
    executable = str(bindir / "ruby")
    row = json.loads(output([executable, "--disable=rubyopt", "-e", RUNTIME], env))
    require((row["version"], row["prefix"], row["ruby"]) == (version, str(prefix), executable),
            "managed Ruby identity mismatch")
    require(row["native_ok"] and row["shared"] == "yes" and row["libraries"] and
            all(prefix in Path(p).parents for p in row["libraries"] + [row["gem_dir"]]), "runtime or library mismatch")
    jits = {"YJIT", "RJIT" if version.startswith("3.4.") else "ZJIT"}
    flags = shlex.split(row["flags"])
    require(set(row["jit_enabled"]) == set(row["jit_build"]) == jits and
            all(row["jit_enabled"][j] is False and row["jit_build"][j] in (None, "", "no") and
                "--disable-" + j.lower() in flags for j in jits), "JIT build or runtime mismatch")
    docs = prefix / "share" / "ri" / row["abi"] / "system"
    require(str(docs) == row["docs"] and prefix in docs.resolve().parents, "unexpected ri store")
    if profile == "custom":
        require("--disable-install-doc" in flags and not any(docs.rglob("*.ri")), "unexpected standard documentation")
        row["standard_docs"] = {"ri_files_found": 0}
    else:
        require({"--enable-install-doc", "--enable-install-rdoc"}.issubset(flags) and
                (docs / "String/cdesc-String.ri").is_file(), "standard documentation missing")
        page = output([str(bindir / "ri"), "--no-pager", "--format=rdoc", "--no-standard-docs",
                       "--doc-dir=" + str(docs), "String"], env)
        require(len(page) > 100 and "String" in page, "ri did not read managed String documentation")
        contents = page.encode("utf-8")
        row["standard_docs"] = {"class": "String", "bytes": len(contents), "sha256": hashlib.sha256(contents).hexdigest()}
    row["commands"] = {}
    for name in ("ruby", "gem", "bundle", "bundler", "irb", "erb", "rdoc", "ri", "rake"):
        path = bindir / name
        require(prefix in path.resolve(strict=True).parents, "command outside prefix: " + name)
        value = output([str(path), "--version"], env, stderr=subprocess.STDOUT)
        require(re.search(r"\d+\.\d+", value), "missing version output: " + name)
        row["commands"][name] = value
    return row


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="operation", required=True)
    compiler = sub.add_parser("rust")
    compiler.add_argument("profile", choices=("default", "custom", "rust"))
    runtime = sub.add_parser("ruby")
    runtime.add_argument("version", choices=("3.4.12", "4.0.9"))
    runtime.add_argument("prefix", type=Path)
    runtime.add_argument("profile", choices=("default", "custom", "rust"))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        env = {"PATH": "/usr/bin:/bin", "HOME": tmp, "LC_ALL": "C", "TZ": "UTC", "TERM": "dumb"}
        result = (rust(args.profile, Path(tmp), env) if args.operation == "rust" else
                  ruby(args.version, args.prefix, args.profile, env))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
