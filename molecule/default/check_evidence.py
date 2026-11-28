"""Validate one completed Molecule condition before its CI job can pass."""
import argparse
import json
from pathlib import Path
import re


STAGES = ("prepare", "converge", "side_effect", "check", "idempotence", "verify")
COUNTERS = {"ok", "changed", "unreachable", "failed", "skipped", "rescued", "ignored"}
BASELINES = {
    "v0.2.0": ("ruby_install_v020", "6b1cd945c5a0d3472c7f1dfe565852db37097596"),
    "v0.3.0": ("ruby_install_v030", "0002dea544bfd6d52b4f0aaa94a4eff5aec54bd5"),
    "v1.0.0": ("ruby_install_v100", "057658e284ae63769722d0c47116b41fb0e5b3f6"),
}
SOURCE_SHA256 = json.loads((Path(__file__).resolve().parents[2] / "tests/fixtures/release_source_sha256.json").read_text())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def play_recaps(log, installer_role=None):
    current = None
    rows = {}
    expected_roles = {}
    if installer_role is not None:
        require(installer_role == "candidate" or installer_role in BASELINES, "unknown installer role")
        first_role = "ruby_install" if installer_role == "candidate" else BASELINES[installer_role][0]
        expected_roles = {"converge": first_role, "check": "ruby_install", "idempotence": "ruby_install"}
    roles = set()
    for line in log.splitlines():
        step = re.search(r"\[default > (\w+)\] Executing$", line)
        if step:
            current = step[1]
            roles.clear()
        if current in expected_roles:
            task = re.match(r"^TASK \[(ruby_install\w*) : ", line)
            if task:
                roles.add(task[1])
        if current in STAGES and re.match(r"^ruby-install-default\s*:", line):
            require(current not in rows, "duplicate target recap for " + current)
            if current in expected_roles:
                require(roles == {expected_roles[current]}, "wrong or missing role in " + current)
            row = {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", line)}
            require(COUNTERS <= row.keys(), "incomplete target recap for " + current)
            require(row["ok"] > 0 and not any(row[k] for k in ("failed", "unreachable", "ignored")),
                    "unsuccessful target recap for " + current)
            rows[current] = row
    require(tuple(rows) == STAGES, "missing or out-of-order Molecule target recaps")
    require(rows["converge"]["changed"] > 0 and rows["check"]["changed"] == rows["idempotence"]["changed"] == 0,
            "unexpected installation or rerun change counts")
    return rows


def resources(settings, state, memory, effective):
    nano, limit, swap_limit, period, quota = (int(s) for s in settings.split())
    require(nano == 1000000000 or (nano == 0 and period > 0 and period == quota), "target CPU limit differs")
    require(limit == swap_limit == 2 * 1024 ** 3, "target memory or swap limit differs")
    require(state["OOMKilled"] is False and state["Running"] is True, "target stopped or was OOM-killed")
    counters = {key: int(value) for key, value in (line.split() for line in memory.splitlines())}
    require(counters.get("oom_kill") == 0 and all(counters.get(k, 0) == 0 for k in ("oom", "oom_group_kill", "under_oom")),
            "OOM or unavailable OOM accounting")
    version, quota, period, memory_max, swap_max = effective.split()
    require(version in ("v1", "v2") and int(quota) == int(period) > 0 and int(memory_max) == limit and
            int(swap_max) == (0 if version == "v2" else limit), "effective cgroup CPU, memory or swap limit differs")
    return {"cgroup_version": version, "cpu": 1, "memory_bytes": limit, "memory_plus_swap_bytes": swap_limit,
            "memory_events": counters}


def distribution_ruby(comparison):
    require(isinstance(comparison, dict), "missing distribution Ruby coexistence evidence")
    before = comparison.get("before")
    require(isinstance(before, dict) and before == comparison.get("after"),
            "distribution Ruby baseline missing or changed")
    require(isinstance(before.get("path"), str) and before["path"].startswith("/usr/")
            and isinstance(before.get("rpm"), str) and before["rpm"]
            and isinstance(before.get("version"), str) and before["version"]
            and all(type(before.get(key)) is int for key in ("mode", "uid", "gid"))
            and isinstance(before.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", before["sha256"]),
            "incomplete distribution Ruby snapshot")


def publication(value, prefix, initial_links=()):
    require(isinstance(value, dict), "missing publication evidence")
    before, created, after = (value.get(key) for key in ("before", "created", "after"))
    require(isinstance(before, dict) and isinstance(after, dict) and created == after, "link rerun changed state")
    protected = {"prefix", "installed_packages", "repository_files"}
    require(set(before) == set(after) == protected | {"public_commands"}, "incomplete publication snapshots")
    for key in protected:
        require(isinstance(before[key], str) and re.fullmatch(r"[0-9a-f]{64}", before[key]) and before[key] == after[key],
                "publication changed protected state: " + key)
    old, new = before["public_commands"], after["public_commands"]
    names = {"ruby", "gem", "bundle", "bundler", "irb", "erb", "rdoc", "ri", "rake"}
    require(isinstance(old, dict) and isinstance(new, dict) and set(old) == set(new) == names, "missing public names")
    require({name for name in names if old[name] != new[name]} == {"ruby", "gem"}, "unexpected public changes")
    for name in initial_links:
        require(isinstance(old[name], str) and re.fullmatch(r"[0-9a-f]{64}", old[name]), "missing first-run link: " + name)
    for name in ("ruby", "gem"):
        require(old[name] is None and isinstance(new[name], str) and re.fullmatch(r"[0-9a-f]{64}", new[name]),
                "selected link did not change from absent to present")
    require(value.get("targets") == [prefix + "/bin/ruby", prefix + "/bin/gem"], "wrong public link targets")


def installation_record(record, version, prefix, docs):
    jit = {"yjit": False, "rjit" if version.startswith("3.4.") else "zjit": False}
    expected = {"schema_version": 1, "state": "complete", "ruby_version": version, "canonical_prefix": prefix,
                "source_sha256": SOURCE_SHA256[version], "documentation": docs, "shared": True, "jit": jit}
    # The record schema distinguishes JSON booleans from numbers.
    require(json.dumps(record, sort_keys=True) == json.dumps(expected, sort_keys=True), "wrong installation record")


def version_mismatch(observation, baseline):
    require(isinstance(observation, dict) and observation.get("requested_version") == "3.4.13"
            and isinstance(observation.get("reason"), str) and observation["reason"].startswith("VERSION_MISMATCH:")
            and observation.get("changed") is False, "missing expected version mismatch")
    require(observation.get("targets") == ["/opt/ruby/bin/ruby", "/opt/ruby/bin/gem"], "wrong v1.0.0 links")
    before = observation.get("before")
    require(isinstance(before, dict) and set(before) == {"prefix", "public_commands", "installed_packages", "repository_files"}
            and all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in before.values()),
            "missing v1.0.0 snapshot")
    require(before == baseline == observation.get("after"), "v1.0.0 protected state changed")


def validate(folder, condition, commit, *, installer_role=None):
    v, _, profile = condition.partition("-")
    require(v in SOURCE_SHA256 and profile in ("default", "custom", "rust"), "unsupported condition")
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "missing Git revision")
    case = json.loads((folder / "case.json").read_text())
    prefix = "/opt/ruby-custom" if profile == "custom" else "/opt/ruby"
    require(case["condition"] == condition, "wrong case")
    # Archived v1.0.0 cases carry the candidate revision in the sibling commit.txt.
    case_commit = case["commit"] if "commit" in case else (folder / "commit.txt").read_text().strip()
    require(case_commit == commit, "case belongs to a different candidate")
    installation_record(case["record"], v, prefix, profile != "custom")
    require(case["after_install"] == case["after_reruns"] and case["workspaces_after_reruns"] == 0 and
            set(case["after_install"]) == {"prefix", "public_commands", "installed_packages", "repository_files"},
            "protected state changed or evidence missing")
    require(case["rust_before"] == case["rust_after"] and case["rust_before"]["installed"] is (profile == "rust"),
            "invalid compiler fixture")
    if v.startswith("3.4.") and profile == "custom":
        distribution_ruby(case.get("os_ruby"))
    result = {"commit": commit, "condition": condition,
              "recaps": play_recaps((folder / "molecule.log").read_text(errors="replace"), case.get("installation_role")),
              "resources": resources((folder / "target-limits.txt").read_text(),
                                     json.loads((folder / "target-state.json").read_text()),
                                     (folder / "memory.txt").read_text(), (folder / "cgroup-limits.txt").read_text())}
    installer = folder / "installer-commit.txt"
    if installer_role or installer.exists() or "publication" in case or "installation_role" in case:
        require(installer.is_file(), "missing installer revision")
        installer_sha = installer.read_text().strip()
        observed_role = case.get("installation_role")
        require(observed_role == "candidate" or observed_role in BASELINES, "missing or unknown installer role")
        expected_sha = commit if observed_role == "candidate" else BASELINES[observed_role][1]
        require(installer_sha == expected_sha, "unexpected installer revision")
        require(installer_role is None or installer_role == observed_role, "unexpected installer role")
        if observed_role == "v1.0.0":
            require(condition == "3.4.12-default", "wrong v1.0.0 baseline condition")
            mismatch = json.loads((folder / "version-mismatch.json").read_text())
            require(mismatch == case.get("version_mismatch"), "version-mismatch evidence differs from case")
            version_mismatch(mismatch, case["after_reruns"])
            result["version_mismatch"] = mismatch
        else:
            prelinked = observed_role == "v0.3.0" or (observed_role == "candidate" and v.startswith("4.0.") and profile == "rust")
            publication(case.get("publication"), prefix, ("bundle", "rake") if prelinked else ())
        result["installation_role"] = observed_role
        result["installer_commit"] = installer_sha
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("condition")
    parser.add_argument("commit")
    parser.add_argument("--installer", choices=("candidate", *BASELINES), help="require publication with this installer")
    args = parser.parse_args()
    result = validate(args.folder, args.condition, args.commit, installer_role=args.installer)
    (args.folder / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
