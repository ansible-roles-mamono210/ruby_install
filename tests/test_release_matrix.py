"""Regression checks for the six-case workflow and its evidence gate."""
import importlib.util
from pathlib import Path
import shlex
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_evidence", ROOT / "molecule/default/check_evidence.py")
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


def recap_log(installer="ruby_install"):
    lines = []
    for stage in evidence.STAGES:
        changed = 5 if stage == "converge" else 0
        lines.append(f"INFO     [default > {stage}] Executing")
        if stage in ("converge", "check", "idempotence"):
            role = installer if stage == "converge" else "ruby_install"
            lines.append(f"TASK [{role} : Inspect Ruby] ***")
        lines.append(f"ruby-install-default  : ok=5 changed={changed} unreachable=0 failed=0 skipped=1 rescued=0 ignored=0")
    return "\n".join(lines)


class ReleaseMatrix(unittest.TestCase):
    def test_publication_requires_only_two_new_links_and_stable_reruns(self):
        names = ("ruby", "gem", "bundle", "bundler", "irb", "erb", "rdoc", "ri", "rake")
        old = {name: None for name in names}
        before = dict(prefix="1" * 64, installed_packages="2" * 64, repository_files="3" * 64, public_commands=old)
        after = dict(before, public_commands=dict(old, ruby="a" * 64, gem="b" * 64))
        result = dict(before=before, created=after, after=after, targets=["/opt/ruby/bin/ruby", "/opt/ruby/bin/gem"])
        evidence.publication(result, "/opt/ruby")
        with self.assertRaises(ValueError):
            evidence.publication(result, "/opt/ruby", ("bundle", "rake"))
        initial = dict(old, bundle="c" * 64, rake="d" * 64)
        preexisting = dict(after, public_commands=dict(initial, ruby="a" * 64, gem="b" * 64))
        evidence.publication(dict(result, before=dict(before, public_commands=initial), created=preexisting,
                                  after=preexisting), "/opt/ruby", ("bundle", "rake"))
        replaced = dict(preexisting, public_commands=dict(preexisting["public_commands"], bundle="f" * 64))
        with self.assertRaises(ValueError):
            evidence.publication(dict(result, before=dict(before, public_commands=initial), created=replaced,
                                      after=replaced), "/opt/ruby", ("bundle", "rake"))
        for change in (dict(prefix="4" * 64), dict(public_commands=dict(after["public_commands"], irb="c" * 64))):
            wrong = dict(after, **change)
            with self.assertRaises(ValueError):
                evidence.publication(dict(result, created=wrong, after=wrong), "/opt/ruby")
        for wrong in (dict(result, created=before), dict(result, targets=["/usr/bin/ruby", "/usr/bin/gem"])):
            with self.assertRaises(ValueError):
                evidence.publication(wrong, "/opt/ruby")

    def test_distribution_ruby_requires_complete_matching_snapshots(self):
        before = {"path": "/usr/bin/ruby", "rpm": "ruby-3.0.7", "version": "3.0.7",
                  "uid": 0, "gid": 0, "mode": 0o100755, "sha256": "a" * 64}
        evidence.distribution_ruby({"before": before, "after": dict(before)})
        for value in (None, {}, {"before": before}, {"before": before, "after": dict(before, version="3.4.12")}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                evidence.distribution_ruby(value)
        for field in before:
            incomplete = {k: v for k, v in before.items() if k != field}
            with self.subTest(field=field), self.assertRaises(ValueError):
                evidence.distribution_ruby({"before": incomplete, "after": dict(incomplete)})

    def test_normal_and_release_lint_use_the_adopted_checks(self):
        config = yaml.safe_load((ROOT / ".circleci/config.yml").read_text())
        self.assertEqual(config["orbs"]["ansible-lint"], "orbss/ansible-lint@1.0.0")
        image = config["parameters"]["ansible_lint_executor_image"]["default"]
        self.assertTrue(image.endswith("@sha256:4ea7fe7ebbe7fd06bd5a7fc61b8931c3303a11c9bd4eb06431a810f5914b8718"))
        job = config["jobs"]["ansible-lint"]
        self.assertEqual(job["executor"]["image"], "<< pipeline.parameters.ansible_lint_executor_image >>")
        self.assertIn({"ansible-lint/execute": {"molecule-role-test": True}}, job["steps"])
        self.assertIn("python3 -B scripts/check_role_variable_names.py --source .",
                      [step["run"]["command"] for step in job["steps"] if isinstance(step, dict) and "run" in step])
        for name in ("build", "v020-release-matrix"):
            self.assertTrue(any(isinstance(item, dict) and "ansible-lint" in item
                                for item in config["workflows"][name]["jobs"]))

    def test_workflow_has_one_sequential_job_per_condition(self):
        config = yaml.safe_load((ROOT / ".circleci/config.yml").read_text())
        jobs = config["workflows"]["v020-release-matrix"]["jobs"]
        cases = [f"{v}-{p}" for v in ("3.4.12", "4.0.9") for p in ("default", "custom", "rust")]
        self.assertEqual(config["jobs"]["v020-role-condition"]["parameters"]["condition"]["enum"], cases)
        self.assertEqual(len(jobs), 5 + len(cases))
        self.assertEqual(jobs[0], "trailing-whitespace")
        self.assertEqual(jobs[1]["yamllint"]["requires"], ["trailing-whitespace"])
        self.assertEqual(jobs[2]["ansible-lint"]["requires"], ["yamllint"])
        self.assertEqual(jobs[3]["molecule"]["requires"], ["ansible-lint"])
        upgrade = jobs[4]["v020-role-condition"]
        self.assertEqual(upgrade, {"name": "upgrade-from-v0.3.0", "condition": "4.0.9-custom",
                                    "installer": "v0.3.0", "requires": [jobs[3]["molecule"]["name"]]})
        job_parameters = config["jobs"]["v020-role-condition"]["parameters"]
        self.assertEqual(job_parameters["installer"]["default"], "candidate")
        previous = upgrade["name"]
        for job, case in zip(jobs[5:], cases):
            row = job["v020-role-condition"]
            self.assertEqual(row, {"condition": case, "name": "ruby-" + case, "requires": [previous]})
            previous = row["name"]

    def test_installer_must_run_first_and_candidate_must_run_both_reruns(self):
        log = recap_log("ruby_install_v030")
        evidence.play_recaps(log, "v0.3.0")
        evidence.play_recaps(recap_log("ruby_install_v020"), "v0.2.0")
        evidence.play_recaps(recap_log(), "candidate")
        for wrong in (recap_log(), recap_log("ruby_install_v020"),
                      log.replace("TASK [ruby_install :", "TASK [ruby_install_v030 :", 1),
                      log.replace("TASK [ruby_install :", "TASK [ruby_install_v030 :"),
                      log.replace("TASK [ruby_install_v030 :", "TASK [ruby_install : Extra]\nTASK [ruby_install_v030 :"),
                      log.replace("TASK [ruby_install_v030 : Inspect Ruby] ***", "")):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                evidence.play_recaps(wrong, "v0.3.0")

    def test_workflows_pass_the_expected_installer_to_the_runner(self):
        config = yaml.safe_load((ROOT / ".circleci/config.yml").read_text())
        for job, expected_argument in (("molecule", "--from-v020"), ("v020-role-condition", "<< parameters.installer >>")):
            commands = [step["run"]["command"] for step in config["jobs"][job]["steps"]
                        if isinstance(step, dict) and "run" in step]
            calls = [shlex.split(line) for line in "\n".join(commands).splitlines()
                     if line.lstrip().startswith("bash molecule/default/run-ci.sh ")]
            self.assertEqual([args[-1] for args in calls], [expected_argument], job)
        preflight = next(item["molecule"] for item in config["workflows"]["build"]["jobs"]
                         if isinstance(item, dict) and item.get("molecule", {}).get("name") == "preflight")
        self.assertIn("feature/v1.0.0-release", preflight["filters"]["branches"]["only"])

    def test_missing_duplicate_failed_and_changed_reruns_do_not_pass(self):
        log = recap_log()
        self.assertEqual(evidence.play_recaps(log)["converge"]["changed"], 5)
        for altered in (log.replace("[default > prepare]", "[default > absent]"),
                        log + "\n" + log, log.replace("unreachable=0", "unreachable=1", 1),
                        log.replace("failed=0", "failed=1", 1), log.replace("changed=0", "changed=1"),
                        log.replace("changed=5", "changed=0"), log.replace("ok=5", "ok=0", 1)):
            with self.subTest(altered=altered), self.assertRaises(ValueError):
                evidence.play_recaps(altered)

    def test_resources_and_oom_accounting_must_be_observable(self):
        state = {"Running": True, "OOMKilled": False}
        limits = "1000000000 2147483648 2147483648 0 0"
        effective = "v2 100000 100000 2147483648 0"
        counters = "oom 0\noom_kill 0\n"
        for settings in (limits, "0 2147483648 2147483648 100000 100000"):
            for observed in (effective, "v1 100000 100000 2147483648 2147483648"):
                self.assertEqual(evidence.resources(settings, state, counters, observed)["cpu"], 1)
        for wrong in ("", "v2 max 100000 2147483648 0", "v2 100000 100000 2147483648 max",
                      "v2 100000 100000 2147483648 1", "v1 100000 100000 2147483648 4294967296"):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                evidence.resources(limits, state, counters, wrong)
        for settings, status, events in ((limits, state, ""), (limits, state, "oom_kill 1"),
                                         (limits, state, "oom 1\noom_kill 0"),
                                         (limits, dict(state, OOMKilled=True), counters),
                                         (limits, dict(state, Running=False), counters),
                                         (limits.replace("1000000000", "0"), state, counters),
                                         (limits.replace("2147483648", "0", 1), state, counters)):
            with self.subTest(settings=settings, status=status, events=events), self.assertRaises(ValueError):
                evidence.resources(settings, status, events, effective)


if __name__ == "__main__":
    unittest.main()
