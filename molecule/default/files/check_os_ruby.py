"""Verify that the distribution Ruby survives installation and both Role reruns."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


BASELINE = Path("/var/tmp/ruby-install-os-ruby.json")
RUBY = Path("/usr/bin/ruby")


def observe():
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/"}

    def output(args):
        return subprocess.check_output(args, env=env, text=True, timeout=15).strip()

    resolved = RUBY.resolve(strict=True)
    package = output(["/usr/bin/rpm", "-qf", str(RUBY)])
    version = output([str(RUBY), "--disable=gems,rubyopt", "-e", "print RUBY_VERSION"])
    if not package or not version or Path("/usr") not in resolved.parents:
        raise ValueError("expected the distribution Ruby under /usr")
    info = resolved.stat()
    return {"path": str(resolved), "rpm": package, "version": version,
            "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
            "uid": info.st_uid, "gid": info.st_gid, "mode": info.st_mode}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("save", "verify"))
    args = parser.parse_args()
    current = observe()
    if args.action == "save":
        os.umask(0o077)
        with BASELINE.open("x") as stream:
            json.dump(current, stream, sort_keys=True)
    else:
        initial = json.loads(BASELINE.read_text())
        if current != initial:
            raise SystemExit("The RPM-owned Ruby changed during the Role runs.")
        print(json.dumps({"before": initial, "after": current}, sort_keys=True))
