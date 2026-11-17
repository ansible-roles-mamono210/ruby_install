"""Real lint controls plus rejection, timeout and cleanup evidence boundaries."""
import copy
import importlib.util
from importlib import metadata
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1] / 'scripts/p1'


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


worker, host = load('lint_container_probe'), load('lint_probe')
try:
    REAL_LINT = metadata.version('ansible-lint') == '26.1.1'
except metadata.PackageNotFoundError:
    REAL_LINT = False


@unittest.skipUnless(REAL_LINT, 'real fixture requires ansible-lint 26.1.1')
class RealLint(unittest.TestCase):
    def test_live_eight_controls(self):
        result = worker.exercise()
        self.assertEqual(result['status'], worker.SUCCESS)
        self.assertEqual([r['exit_code'] for r in result['cases']], [0, 0, 0, 2, 2, 2, 2, 2])
        self.assertEqual(sum(len(r['diagnostics']) for r in result['cases']), 11)
        self.assertTrue(result['temporary_directory_removed'])
        self.assertTrue(result['fixture_inputs_unchanged'])
        self.assertFalse(result['full_role_lint_passed'])

    def test_disabling_the_rule_is_detected(self):
        with patch.object(worker, 'CONFIG', '---\nwarn_list: []\nskip_list: [var-naming]\n'):
            with self.assertRaisesRegex(worker.Stop, '^LINT_DIAGNOSTICS$') as caught:
                worker.exercise()
        self.assertEqual(caught.exception.diagnostic['case'], 'legacy_defaults')
        self.assertEqual(caught.exception.diagnostic['exit_code'], 0)


class Boundary(unittest.TestCase):
    @staticmethod
    def valid_schema():
        # Synthetic envelope tests validation; it is never saved as CI evidence.
        return {'schema': worker.SCHEMA, 'status': worker.SUCCESS,
                'scope': 'disposable_variable_files_all_default_rules',
                'packages': {k: '26.1.1' if k == 'ansible-lint' else '1.0' for k in worker.PACKAGES},
                'python': '3.14.0', 'arch': 'x86_64', 'uid': 1000, 'isolation_checked': True,
                'cases': [{'case': c[0], 'exit_code': 2 if c[3] else 0, 'diagnostics': worker.expected(c),
                           'stdout_sha256': '0' * 64, 'stderr_sha256': '1' * 64,
                           'stderr_class': 'expected_violation_summary' if c[3] else 'expected_pass_summary'}
                          for c in worker.CASES],
                'elapsed_seconds': 10.0, 'config_sha256': host.hashlib.sha256(worker.CONFIG.encode()).hexdigest(),
                'temporary_directory_removed': True, 'fixture_inputs_unchanged': True,
                'role_verified': False, 'full_role_lint_passed': False, 'phase1_complete': False}

    def test_schema_rejects_missing_controls_and_false_completion(self):
        good = self.valid_schema()
        host.validate(good)
        for mutation in ('missing_case', 'missing_variable', 'wrong_rule', 'bool_code', 'zero_uid',
                         'wrong_python', 'nan_time', 'role_claim', 'phase_claim', 'unclassified_field'):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(good)
                if mutation == 'missing_case': bad['cases'].pop()
                if mutation == 'missing_variable': bad['cases'][3]['diagnostics'].pop()
                if mutation == 'wrong_rule': bad['cases'][3]['diagnostics'][0]['rule'] = 'yaml'
                if mutation == 'bool_code': bad['cases'][0]['exit_code'] = False
                if mutation == 'zero_uid': bad['uid'] = 0
                if mutation == 'wrong_python': bad['python'] = '3.12.14'
                if mutation == 'nan_time': bad['elapsed_seconds'] = float('nan')
                if mutation == 'role_claim': bad['full_role_lint_passed'] = True
                if mutation == 'phase_claim': bad['phase1_complete'] = True
                if mutation == 'unclassified_field': bad['credential'] = 'dummy-secret'
                with self.assertRaises(host.Stop): host.validate(bad)

    def test_zero_diagnostics_never_proves_a_negative_control(self):
        result = subprocess.CompletedProcess([], 0, '[]', '')
        with self.assertRaisesRegex(worker.Stop, '^LINT_DIAGNOSTICS$'):
            worker.check_output(result, worker.CASES[3])

    def test_unknown_stderr_rejected(self):
        result = subprocess.CompletedProcess([], 0, '[]', 'dummy-secret')
        with self.assertRaisesRegex(worker.Stop, '^LINT_STDERR$') as caught:
            worker.check_output(result, worker.CASES[0])
        self.assertNotIn('dummy-secret', str(caught.exception))

    def test_untrusted_worker_output_not_persisted(self):
        for rc, out, err in ((0, 'dummy-secret', ''), (0, '{}', 'dummy-secret'),
                             (3, '{"status":"INCOMPLETE","reason":"dummy-secret","diagnostic":null}', '')):
            with self.subTest(rc=rc, out=out), patch.object(host.subprocess, 'run',
                    return_value=subprocess.CompletedProcess([], rc, out, err)):
                with self.assertRaises(host.Stop) as caught:
                    host.run_worker([], '', time.monotonic() + 10)
                self.assertNotIn('dummy-secret', str(caught.exception))

    def test_bounded_safe_failure_diagnostic_is_retained(self):
        diagnostic = {'case': 'legacy_defaults', 'exit_code': 0, 'stdout_bytes': 3, 'stderr_bytes': 0,
                      'stdout_sha256': 'a' * 64, 'stderr_sha256': 'b' * 64}
        row = {'status': 'INCOMPLETE', 'reason': 'LINT_DIAGNOSTICS', 'diagnostic': diagnostic}
        with patch.object(host.subprocess, 'run', return_value=subprocess.CompletedProcess([], 3, json.dumps(row), '')):
            with self.assertRaisesRegex(host.Stop, '^WORKER_LINT_DIAGNOSTICS$') as caught:
                host.run_worker([], '', time.monotonic() + 10)
        self.assertEqual(caught.exception.diagnostic, diagnostic)

    def test_container_has_no_network_or_repository_mount(self):
        args = host.arguments(load('target_probe'), 'test-name', 'test-run')
        for flag, value in (('--network', 'none'), ('--user', 'circleci'), ('--cap-drop', 'ALL'),
                            ('--memory', '512m'), ('--memory-swap', '512m'), ('--cpus', '1')):
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertIn('--read-only', args)
        self.assertIn('/tmp:rw,nosuid,nodev,noexec,size=128m,mode=1777', args)
        self.assertNotIn('--volume', args)
        self.assertNotIn('--privileged', args)
        compile(host.payload(), '<lint-payload>', 'exec')

    def test_unapproved_environment_stops_before_docker(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(host.os.environ, {}, clear=True), \
                patch.object(host.subprocess, 'run') as run:
            output = Path(directory) / 'result.json'
            self.assertEqual(host.main(['--output', str(output)]), 3)
            self.assertEqual(json.loads(output.read_text())['reason'], 'EXPLICIT_EPHEMERAL_CI_REQUIRED')
            run.assert_not_called()

    def test_timeout_cleanup_and_cleanup_failure(self):
        for clean in (True, False):
            with self.subTest(clean=clean):
                target = load('target_probe')
                target.command = Mock(return_value='')
                target.cleanup = Mock(return_value=clean)
                inventory = SimpleNamespace(now=lambda: '2026-11-17T00:00:00Z',
                    registry_identity=lambda *_: {'platform_manifest_digest': host.MANIFEST,
                                                  'config_digest': host.CONFIG, 'index_digest': None})
                modules = {'target_probe': target, 'env_probe': inventory, 'lint_container_probe': worker}
                original_stat = host.os.stat

                def fixture_stat(path, *args, **kwargs):
                    if str(path) == '/var/run/docker.sock':
                        return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0)
                    return original_stat(path, *args, **kwargs)

                with tempfile.TemporaryDirectory() as directory, \
                        patch.dict(host.os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': host.BRANCH,
                                                     'CIRCLE_SHA1': 'e' * 40}, clear=True), \
                        patch.object(host, 'load', side_effect=lambda n: modules[n]), \
                        patch.object(host.os, 'stat', side_effect=fixture_stat), \
                        patch.object(host, 'inspect_image', return_value={}), \
                        patch.object(host, 'run_worker', side_effect=host.Stop('WORKER_TIMEOUT')):
                    output = Path(directory) / 'result.json'
                    self.assertEqual(host.main(['--output', str(output), '--allow-pull', '--ephemeral-ci', '--allow-lint-fixture']), 3)
                    saved = json.loads(output.read_text())
                    self.assertEqual(saved['reason'], 'WORKER_TIMEOUT' if clean else 'CLEANUP_UNCONFIRMED')
                    self.assertEqual(saved['cleanup']['container_removed'], clean)
                    self.assertNotIn('result', saved)
                name, run_id = target.cleanup.call_args.args
                self.assertEqual(name, 'ruby-p1-' + run_id + '-lint-r45')


if __name__ == '__main__':
    unittest.main()
