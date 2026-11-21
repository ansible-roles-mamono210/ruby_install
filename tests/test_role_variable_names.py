"""Real source controls, traversal boundaries and host evidence validation."""
import base64
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

ROOT = Path(__file__).resolve().parents[1]


def p1_snapshot():
    # The Phase 1 controls compare against the original legacy variable names.
    raw = (ROOT / 'tests/fixtures/p1_role_defaults.txt').read_bytes()
    return {'defaults/main.yml': base64.b64encode(raw).decode('ascii')}


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = load('real_variables', 'scripts/check_role_variable_names.py')
worker = load('real_variable_worker', 'scripts/p1/role_vars_container_probe.py')
host = load('real_variable_host', 'scripts/p1/role_vars_probe.py')
try:
    REAL_LINT = metadata.version('ansible-lint') == '26.1.1'
except metadata.PackageNotFoundError:
    REAL_LINT = False


@unittest.skipUnless(REAL_LINT, 'requires ansible-lint 26.1.1')
class RealControls(unittest.TestCase):
    def test_real_source_and_eight_controls_with_host_validation(self):
        result = worker.run(checker, p1_snapshot(), host.SOURCE_HASH)
        self.assertEqual([c['result']['exit_code'] for c in result['cases']], [2, 0, 2, 2, 3, 3, 3, 3])
        self.assertEqual(sum(len(c['result'].get('diagnostics', [])) for c in result['cases']), 6)
        # Synthetic runtime fields exercise the host validator, never become CI evidence.
        valid = dict(result, isolation_checked=True, uid=3434, python='3.14.3')
        host.validate(valid)
        for change in ('case', 'rule', 'line', 'hash', 'claim', 'extra', 'code', 'nan', 'uid', 'cleanup'):
            with self.subTest(change=change):
                bad = copy.deepcopy(valid)
                if change == 'case': bad['cases'].pop()
                if change == 'rule': bad['cases'][0]['result']['diagnostics'][0]['rule'] = 'yaml'
                if change == 'line': bad['cases'][0]['result']['diagnostics'][0]['location']['positions']['begin']['line'] = True
                if change == 'hash': bad['cases'][0]['result']['source_sha256']['defaults/main.yml'] = '0' * 64
                if change == 'claim': bad['full_role_lint_passed'] = True
                if change == 'extra': bad['cases'][4]['result']['extra'] = 'untrusted'
                if change == 'code': bad['cases'][1]['result']['exit_code'] = False
                if change == 'nan': bad['elapsed_seconds'] = float('nan')
                if change == 'uid': bad['uid'] = 0
                if change == 'cleanup': bad['temporary_directory_removed'] = False
                with self.assertRaises(host.Stop): host.validate(bad)

    def test_current_defaults_pass_variable_naming(self):
        self.assertEqual(checker.check(ROOT)['exit_code'], 0)

    def test_disabling_rule_is_detected(self):
        with patch.object(checker, 'CONFIG', '---\nwarn_list: []\nskip_list: [var-naming]\n'):
            with self.assertRaisesRegex(worker.Stop, '^CONTROL_MATRIX$'):
                worker.run(checker, p1_snapshot(), host.SOURCE_HASH)

    def test_unknown_stderr_and_zero_processed_are_rejected(self):
        snapshot = {'defaults/main.yml': checker.base64.b64encode(b'---\nruby_install_version: fixture\n').decode()}
        valid = "\nPassed: 0 failure(s), 0 warning(s) in 1 files processed of 1 encountered. Last profile that met the validation criteria was 'production'.\n"
        for stderr in (valid + 'unexpected\n', valid.replace('1 files processed', '0 files processed')):
            with self.subTest(stderr=stderr), patch.object(checker.subprocess, 'run',
                    return_value=subprocess.CompletedProcess([], 0, '[]', stderr)):
                with self.assertRaisesRegex(checker.Stop, '^LINT_STDERR$'):
                    checker.run_snapshot(snapshot)

    def test_source_change_after_lint_is_rejected(self):
        before = checker.collect(ROOT)
        with patch.object(checker, 'collect', side_effect=[before, {}]):
            with self.assertRaisesRegex(checker.Stop, '^SOURCE_CHANGED$'):
                checker.check(ROOT)


class Boundaries(unittest.TestCase):
    def test_collect_nested_yaml_and_reject_empty_symlink_hardlink_fifo(self):
        for kind, reason in (('empty', 'NO_VARIABLE_FILES'), ('symlink', 'SOURCE_SYMLINK'),
                             ('hardlink', 'SOURCE_SPECIAL_FILE'), ('fifo', 'SOURCE_SPECIAL_FILE'),
                             ('extension', 'SOURCE_PATH')):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                target = root / 'defaults/main.yml'
                target.parent.mkdir()
                if kind == 'symlink': target.symlink_to(ROOT / 'defaults/main.yml')
                elif kind == 'hardlink':
                    target.write_text('---\nx: 1\n')
                    checker.os.link(target, root / 'linked')
                elif kind == 'fifo': checker.os.mkfifo(target)
                elif kind == 'extension': target.with_suffix('.txt').write_text('ignored?')
                with self.assertRaisesRegex(checker.Stop, '^' + reason + '$'): checker.collect(root)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'vars/nested/file.yaml'
            target.parent.mkdir(parents=True)
            target.write_text('---\nruby_install_x: 1\n')
            self.assertEqual(set(checker.collect(tmp)), {'vars/nested/file.yaml'})

    def test_decode_rejects_traversal_suppression_and_invalid_mapping(self):
        enc = lambda text: checker.base64.b64encode(text.encode()).decode()
        for snapshot, reason in (({'defaults/../main.yml': enc('x: 1')}, 'INVALID_SNAPSHOT'),
                                 ({'defaults/main.yml': enc('x: 1 # noqa')}, 'INLINE_SUPPRESSION'),
                                 ({'defaults/main.yml': enc('# yamllint disable\nx: 1')}, 'INLINE_SUPPRESSION'),
                                 ({'defaults/main.yml': enc('---\n- x')}, 'INVALID_VARIABLE_MAPPING'),
                                 ({'defaults/main.yml': enc('')}, 'INVALID_VARIABLE_MAPPING')):
            with self.subTest(reason=reason), self.assertRaisesRegex(checker.Stop, '^' + reason + '$'):
                checker.decode(snapshot)

    def test_container_isolation_and_payload_compiles(self):
        args = host.arguments(host.load('target_probe'), 'unit-test', 'unit-run')
        for flag, value in (('--network', 'none'), ('--user', 'circleci'), ('--memory', '512m'),
                            ('--memory-swap', '512m'), ('--cpus', '1')):
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertIn('--read-only', args)
        self.assertIn('/tmp:rw,nosuid,nodev,noexec,size=128m,mode=1777', args)
        self.assertNotIn('--volume', args)
        self.assertNotIn('--privileged', args)
        compile(host.payload(checker.collect(ROOT)), '<role-vars-payload>', 'exec')

    def test_worker_untrusted_output_and_timeout_rejected(self):
        for rc, out, err in ((0, 'untrusted', ''), (0, '{}', 'untrusted'),
                             (3, '{"status":"INCOMPLETE","reason":"untrusted"}', '')):
            with patch.object(host.subprocess, 'run', return_value=subprocess.CompletedProcess([], rc, out, err)):
                with self.assertRaises(host.Stop) as caught: host.run_worker([], '', time.monotonic() + 10)
                self.assertNotIn('untrusted', str(caught.exception))
        with patch.object(host.subprocess, 'run', side_effect=subprocess.TimeoutExpired([], 1)):
            with self.assertRaisesRegex(host.Stop, '^WORKER_TIMEOUT$'): host.run_worker([], '', time.monotonic() + 10)

    def test_unapproved_environment_and_existing_output_stop(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(host.os.environ, {}, clear=True), patch.object(host.subprocess, 'run') as run:
            output = Path(tmp) / 'out.json'
            self.assertEqual(host.main(['--output', str(output)]), 3)
            data = output.read_bytes()
            self.assertEqual(json.loads(data)['reason'], 'EXPLICIT_EPHEMERAL_CI_REQUIRED')
            self.assertEqual(host.main(['--output', str(output)]), 3)
            self.assertEqual(output.read_bytes(), data)
            run.assert_not_called()

    def test_timeout_cleanup_and_cleanup_failure(self):
        for clean in (True, False):
            target = host.load('target_probe')
            target.command = Mock(return_value='')
            target.cleanup = Mock(return_value=clean)
            inventory = SimpleNamespace(now=lambda: '2026-11-17T00:00:00Z', registry_identity=lambda *_:
                {'platform_manifest_digest': host.MANIFEST, 'config_digest': host.CONFIG, 'index_digest': None})
            modules = {'target_probe': target, 'env_probe': inventory, 'role_vars_container_probe': worker,
                       '../check_role_variable_names': checker}
            original_stat = host.os.stat
            def fixture_stat(path, *args, **kwargs):
                if str(path) == '/var/run/docker.sock':
                    return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0)
                return original_stat(path, *args, **kwargs)
            with tempfile.TemporaryDirectory() as tmp, patch.dict(host.os.environ,
                    {'CIRCLECI': 'true', 'CIRCLE_BRANCH': host.BRANCH, 'CIRCLE_SHA1': 'e' * 40}, clear=True), \
                    patch.object(host, 'load', side_effect=lambda n: modules[n]), \
                    patch.object(host.os, 'stat', side_effect=fixture_stat), \
                    patch.object(host, 'inspect_image', return_value={}), \
                    patch.object(checker, 'collect', return_value=p1_snapshot()), \
                    patch.object(host, 'run_worker', side_effect=host.Stop('WORKER_TIMEOUT')):
                output = Path(tmp) / 'result.json'
                self.assertEqual(host.main(['--output', str(output), '--allow-pull', '--ephemeral-ci', '--allow-role-vars']), 3)
                saved = json.loads(output.read_text())
                self.assertEqual(saved['reason'], 'WORKER_TIMEOUT' if clean else 'CLEANUP_UNCONFIRMED')
                self.assertEqual(saved['cleanup']['container_removed'], clean)
                self.assertNotIn('result', saved)
            name, run_id = target.cleanup.call_args.args
            self.assertEqual(name, 'ruby-p1-' + run_id + '-role-vars-r47')


if __name__ == '__main__':
    unittest.main()
