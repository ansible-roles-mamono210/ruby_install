"""Validate one completed Molecule condition before its CI job can pass."""
import argparse
import json
from pathlib import Path
import re


STAGES = ("prepare", "converge", "side_effect", "check", "idempotence", "verify")
COUNTERS = {"ok", "changed", "unreachable", "failed", "skipped", "rescued", "ignored"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def play_recaps(log):
    current = None
    rows = {}
    for line in log.splitlines():
        step = re.search(r"\[default > (\w+)\] Executing$", line)
        if step:
            current = step[1]
        if current in STAGES and re.match(r"^ruby-install-default\s*:", line):
            require(current not in rows, "duplicate target recap for " + current)
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


def validate(folder, condition, commit):
    require(re.fullmatch(r"(3\.4\.12|4\.0\.9)-(default|custom|rust)", condition), "unsupported condition")
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "missing Git revision")
    case = json.loads((folder / "case.json").read_text())
    v, profile = condition.split("-")
    record = case["record"]
    prefix = "/opt/ruby-custom" if profile == "custom" else "/opt/ruby"
    require(case["condition"] == condition and record["state"] == "complete" and record["ruby_version"] == v and
            record["canonical_prefix"] == prefix and record["documentation"] is (profile != "custom"),
            "wrong case or installation record")
    require(case["after_install"] == case["after_reruns"] and case["workspaces_after_reruns"] == 0 and
            set(case["after_install"]) == {"prefix", "public_commands", "installed_packages", "repository_files"},
            "protected state changed or evidence missing")
    require(case["rust_before"] == case["rust_after"] and case["rust_before"]["installed"] is (profile == "rust"),
            "invalid compiler fixture")
    return {"commit": commit, "condition": condition,
            "recaps": play_recaps((folder / "molecule.log").read_text(errors="replace")),
            "resources": resources((folder / "target-limits.txt").read_text(),
                                   json.loads((folder / "target-state.json").read_text()),
                                   (folder / "memory.txt").read_text(), (folder / "cgroup-limits.txt").read_text())}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("condition")
    parser.add_argument("commit")
    args = parser.parse_args()
    result = validate(args.folder, args.condition, args.commit)
    (args.folder / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
