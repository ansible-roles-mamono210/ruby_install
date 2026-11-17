"""Check v0.1.0 candidate distribution and evaluation regressions in CI."""
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import unittest

import yaml

BASE = "55a7ebfa6c6358ea03563d9ab6741921b2be03dc"
REPOSITORY = "https://github.com/ansible-roles-mamono210/ruby_install.git"
DISTRIBUTION = {
    "README.md", "meta/main.yml", "LICENSE", "CHANGELOG.md",
    "docs/releases/v0.1.0.md", "docs/p1-evidence.md", ".circleci/config.yml",
}
TEST_HASHES = {'tests/test_dependency_probe.py': '7716459d9b4457329a74184a53ff3c2dfc084a81aff490a69524f4c21511aa94', 'tests/test_runtime_smoke.py': 'efa062d15350fdb9d1232ee56f8b360d5a7d4c261bc828c60fe63e503704d9b5', 'tests/test_build_probe.py': 'cf44b31681ddfb3f3c62fb7494ab3298d8700586cf8ee55358edcf6293d52da8'}
ALLOWED = DISTRIBUTION | set(TEST_HASHES) | {"scripts/release/check_v010.py"}
LINT_IDS = {
    "test_lint_probe.RealLint.test_live_eight_controls",
    "test_lint_probe.RealLint.test_disabling_the_rule_is_detected",
    "test_role_variable_names.RealControls.test_real_source_and_eight_controls_with_host_validation",
    "test_role_variable_names.RealControls.test_disabling_rule_is_detected",
    "test_role_variable_names.RealControls.test_unknown_stderr_and_zero_processed_are_rejected",
    "test_role_variable_names.RealControls.test_source_change_after_lint_is_rejected",
}
OUT = Path("v010-evidence")
OUT.mkdir(exist_ok=True)
MODE = os.environ["V010_CHECK_MODE"]
REPORT = {"mode": MODE, "status": "started", "release_ready": False}


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def git(*args, cwd=None):
    return subprocess.check_output(["git", *args], cwd=cwd).decode().strip()


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item.id()


class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started_ids = []
        self.success_ids = []

    def startTest(self, test):
        self.started_ids.append(test.id())
        super().startTest(test)

    def addSuccess(self, test):
        self.success_ids.append(test.id())
        super().addSuccess(test)


def main():
    require(MODE in {"controller", "lint"}, "unknown check mode")
    expected = ("3.14.10", "2.21.6") if MODE == "controller" else ("3.14.3", "2.20.3")
    actual = (platform.python_version(), metadata.version("ansible-core"))
    REPORT["environment"] = {
        "python": actual[0], "ansible_core": actual[1],
        "configured_image": os.environ["V010_IMAGE"],
        "architecture": platform.machine(),
    }
    require(actual == expected, "fixed Python/core version mismatch")
    require(platform.machine() == "x86_64", "unexpected architecture")
    if MODE == "lint":
        lint = metadata.version("ansible-lint")
        REPORT["environment"]["ansible_lint"] = lint
        require(lint == "26.1.1", "fixed lint version mismatch")

    sha = os.environ["CIRCLE_SHA1"]
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "invalid candidate SHA")
    require(git("rev-parse", "HEAD") == sha, "checkout SHA mismatch")
    subprocess.run(["git", "merge-base", "--is-ancestor", BASE, sha], check=True)
    require(not git("diff", "--name-only", "HEAD"), "modified tracked checkout")
    changed = git("diff", "--name-status", "--no-renames", BASE, sha).splitlines()
    for change in changed:
        status, path = change.split("\t")
        require(status in {"A", "M"} and path in ALLOWED, "unplanned source change")
    REPORT.update(candidate_sha=sha, base_sha=BASE, changed=changed)
    for path, expected_hash in TEST_HASHES.items():
        require(hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected_hash,
                "pinned regression test hash mismatch")
    paths = git("ls-tree", "-r", "--name-only", sha).splitlines()
    hashes = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in paths}
    (OUT / "candidate-sha256.json").write_text(json.dumps(hashes, indent=2) + "\n")
    REPORT["source_guard"] = "seven distribution paths, three hash-pinned regression test files and the CI checker"

    loader = unittest.TestLoader()
    if MODE == "controller":
        suite = loader.discover("tests", pattern="test_*.py")
    else:
        suite = unittest.TestSuite([
            loader.discover("tests", pattern="test_lint_probe.py"),
            loader.discover("tests", pattern="test_role_variable_names.py"),
        ])
    ids = list(flatten(suite))
    expected_count = 582 if MODE == "controller" else 20
    require(len(ids) == len(set(ids)) == expected_count, "unexpected collected test IDs")
    require(LINT_IDS <= set(ids), "required lint test IDs not collected")
    with (OUT / "unittest.log").open("w") as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    skipped = [{"id": t.id(), "reason": why} for t, why in result.skipped]
    REPORT["tests"] = {
        "collected": ids, "started": result.started_ids, "passed": result.success_ids,
        "run": result.testsRun, "skipped": skipped,
        "failures": len(result.failures), "errors": len(result.errors),
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
    }
    require(result.wasSuccessful() and not result.expectedFailures, "regression failed")
    require(set(result.started_ids) == set(ids), "not every collected test started")
    skipped_ids = {x["id"] for x in skipped}
    require(skipped_ids <= (LINT_IDS if MODE == "controller" else set()), "unexpected skip")
    if MODE == "lint":
        require(LINT_IDS <= set(result.success_ids), "lint controls did not pass")
    REPORT["lint_complement_required"] = sorted(skipped_ids)

    if MODE == "controller":
        for path in DISTRIBUTION:
            require(Path(path).is_file(), "distribution file missing: " + path)
            data = Path(path).read_bytes()
            require(data.endswith(b"\n") and b"\r" not in data, "non-LF file: " + path)
            require(all(line == line.rstrip(b" \t") for line in data.splitlines()),
                    "trailing whitespace: " + path)
        meta = yaml.safe_load(Path("meta/main.yml").read_text())["galaxy_info"]
        yaml.safe_load(Path(".circleci/config.yml").read_text())
        require(meta["license"] == "BSD-3-Clause", "license metadata not finalized")
        require("min_ansible_version" not in meta and "platforms" not in meta,
                "unverified support declaration")
        for path in ("README.md", "CHANGELOG.md", "docs/releases/v0.1.0.md"):
            require("v0.1.0" in Path(path).read_text(), "release version missing")
        REPORT["license"] = "file and identifier checked; ownership/provenance require human confirmation"

        with tempfile.TemporaryDirectory(prefix="v010-fetch-") as directory:
            git("init", "--quiet", directory)
            git("fetch", "--quiet", "--depth=1", REPOSITORY, sha, cwd=directory)
            git("checkout", "--quiet", "--detach", "FETCH_HEAD", cwd=directory)
            require(git("rev-parse", "HEAD", cwd=directory) == sha, "retrieval SHA mismatch")
            require(git("ls-tree", "-r", "--name-only", sha, cwd=directory).splitlines() == paths,
                    "retrieval file list mismatch")
            retrieved = {p: hashlib.sha256((Path(directory) / p).read_bytes()).hexdigest() for p in paths}
            require(retrieved == hashes, "retrieved bytes differ")
        REPORT["retrieval"] = {"commit": sha, "files": len(paths), "matched": True}
    require(not git("diff", "--name-only", "HEAD"), "tests changed tracked checkout")
    REPORT["status"] = "limited_checks_passed"
    REPORT["release_ready"] = False
    REPORT["remaining"] = "human document/license review, both jobs and trigger/cleanup review, then publication authorization"


try:
    main()
except Exception as exc:
    REPORT["status"] = "failed"
    REPORT["error_type"] = type(exc).__name__
    # Full unittest diagnostics go to a job artifact; environment/credentials are not dumped.
    print("v0.1.0 check failed:", type(exc).__name__, file=sys.stderr)
    raise
finally:
    (OUT / "result.json").write_text(json.dumps(REPORT, indent=2) + "\n")
    print(json.dumps({"mode": MODE, "status": REPORT["status"], "release_ready": False}))
