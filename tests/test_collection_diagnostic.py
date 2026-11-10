"""Offline diagnostic regressions. No Docker, registry, CircleCI or Galaxy access."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/p1' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


c = load('container_diagnostic', 'container_probe.py')
p = load('host_diagnostic', 'env_probe.py')


def row(ok):
    return {'status': 'COLLECTED', 'cleanup_confirmed': True,
            'probe': {'collections_status': 'COLLECTED' if ok else 'COMMAND_FAILED',
                      'collections_diagnostic': {'state': 'EXITED', 'returncode': 0 if ok else 1}}}


def pairs():
    return {kind + '_' + mode: row(mode == 'tmp')
            for kind in p.DIAGNOSTIC_IMAGES for mode in ('original', 'tmp')}


class CollectionDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.signals = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}

    def tearDown(self):
        for s, handler in self.signals.items():
            signal.signal(s, handler)

    def test_failure_metadata_does_not_return_raw_output_or_credentials(self):
        secret = b'credential=PRIVATE_FIXTURE_MUST_NOT_LEAK'
        result = subprocess.CompletedProcess([], 1, secret, b'[Errno 30] Read-only file system /private/' + secret)
        with patch.object(c.subprocess, 'run', return_value=result):
            diagnostic, text = c.collection_command()
        self.assertEqual(diagnostic['returncode'], 1)
        self.assertEqual(diagnostic['stderr_hints'], ['READ_ONLY_FILESYSTEM'])
        self.assertEqual(diagnostic['stderr_bytes'], len(result.stderr))
        self.assertEqual(text, '')
        self.assertNotIn('PRIVATE_FIXTURE', json.dumps(diagnostic))
        self.assertNotIn('/private/', json.dumps(diagnostic))

    def test_success_stdout_is_available_for_json_parsing_only(self):
        result = subprocess.CompletedProcess([], 0, b'{"collection": {}}', b'')
        with patch.object(c.subprocess, 'run', return_value=result) as call:
            diagnostic, text = c.collection_command()
        self.assertEqual(diagnostic['state'], 'EXITED')
        self.assertEqual(text, '{"collection": {}}')
        self.assertEqual(call.call_args.args[0], ['ansible-galaxy', 'collection', 'list', '--format', 'json'])
        self.assertEqual(call.call_args.kwargs['stdin'], subprocess.DEVNULL)

    def test_timeout_is_distinct_and_does_not_expose_partial_output(self):
        error = subprocess.TimeoutExpired('private-command', 30, output=b'SECRET', stderr=b'private SECRET')
        with patch.object(c.subprocess, 'run', side_effect=error):
            diagnostic, text = c.collection_command()
        self.assertEqual(diagnostic['state'], 'TIMEOUT')
        self.assertIsNone(diagnostic['returncode'])
        self.assertNotIn('SECRET', json.dumps(diagnostic))
        self.assertEqual(text, '')

    def test_os_error_persists_only_numeric_errno(self):
        with patch.object(c.subprocess, 'run', side_effect=PermissionError(13, 'SECRET')):
            diagnostic, text = c.collection_command()
        self.assertEqual(diagnostic['state'], 'OS_ERROR')
        self.assertEqual(diagnostic['errno'], 13)
        self.assertNotIn('SECRET', json.dumps(diagnostic))
        self.assertEqual(text, '')

    def test_unknown_stderr_is_not_copied_into_hints(self):
        result = subprocess.CompletedProcess([], 9, b'', b'unclassified SECRET')
        with patch.object(c.subprocess, 'run', return_value=result):
            diagnostic, _ = c.collection_command()
        self.assertEqual(diagnostic['stderr_hints'], [])
        self.assertNotIn('SECRET', json.dumps(diagnostic))

    def test_large_output_cannot_be_reported_as_success(self):
        result = subprocess.CompletedProcess([], 0, b'x' * (8 * 1024 * 1024 + 1), b'')
        with patch.object(c.subprocess, 'run', return_value=result):
            diagnostic, text = c.collection_command()
        self.assertEqual(diagnostic['state'], 'OUTPUT_TOO_LARGE')
        self.assertEqual(text, '')

    def test_original_failure_and_tmp_success_are_separately_preserved(self):
        comparisons, complete = p.diagnostic_summary(pairs())
        self.assertTrue(complete)
        self.assertEqual(set(comparisons.values()), {'TEMP_CACHE_SUCCEEDED'})

    def test_both_success_does_not_claim_cache_caused_failure(self):
        images = pairs()
        images['controller_original'] = row(True)
        comparisons, complete = p.diagnostic_summary(images)
        self.assertTrue(complete)
        self.assertEqual(comparisons['controller'], 'BOTH_SUCCEEDED')

    def test_missing_timeout_invalid_output_or_cleanup_failure_stays_incomplete(self):
        for failure in ('missing', 'timeout', 'invalid', 'cleanup', 'still_failed'):
            with self.subTest(failure=failure):
                images = pairs()
                if failure == 'missing':
                    images.pop('controller_original')
                elif failure == 'timeout':
                    images['controller_original']['probe']['collections_diagnostic']['state'] = 'TIMEOUT'
                elif failure == 'invalid':
                    images['controller_original']['probe']['collections_status'] = 'INVALID_OUTPUT'
                elif failure == 'cleanup':
                    images['controller_original']['cleanup_confirmed'] = False
                else:
                    images['controller_tmp'] = row(False)
                self.assertFalse(p.diagnostic_summary(images)[1])

    def test_requested_digest_mismatch_stops_before_manifest_request(self):
        requested = 'example.test/image@sha256:' + '1' * 64
        info = {'id': 'sha256:' + '3' * 64,
                'repo_digests': ['example.test/image@sha256:' + '2' * 64]}
        with patch.object(p, 'parsed', side_effect=AssertionError('network must not be called')):
            with self.assertRaisesRegex(p.Stop, '^REQUESTED_DIGEST_MISMATCH$'):
                p.registry_identity(requested, info, None)

    def test_requested_digest_can_be_resolved_without_tag_parsing_bug(self):
        requested = 'example.test/image@sha256:' + '1' * 64
        info = {'id': 'sha256:' + '3' * 64, 'repo_digests': [requested]}
        with patch.object(p, 'parsed', return_value={'config': {'digest': info['id']}}):
            self.assertEqual(p.registry_identity(requested, info, None)['registry_reference'], requested)

    def test_tmp_changes_only_one_container_env_argument(self):
        info = {'id': 'sha256:' + '1' * 64, 'os': 'linux', 'arch': 'amd64'}
        probe = {'arch': 'x86_64', 'packages': {'ansible-lint': '26.1.1'}}
        commands = []
        for mode in (None, 'tmp'):
            with patch.object(p, 'parsed', side_effect=[info, copy.deepcopy(probe)]) as parsed, patch.object(p, 'registry_identity', return_value={}), patch.object(p, 'cleanup', return_value=True):
                p.collect_image('lint', p.DIAGNOSTIC_IMAGES['lint'], False, 'run', None, 'pass', galaxy_cache=mode)
                commands.append(parsed.call_args_list[1].args[0])
        modified = commands[1].copy()
        index = modified.index('ANSIBLE_GALAXY_CACHE_DIR=/tmp/ansible-galaxy-cache')
        del modified[index-1:index+1]
        self.assertEqual(commands[0], modified)
        for flag in ('--read-only', '--network', 'none', '--cap-drop', 'ALL', 'no-new-privileges'):
            self.assertIn(flag, modified)
        self.assertNotIn('--privileged', modified)

    def run_main_fixture(self, result_fn):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'evidence.json'
            original_stat = p.os.stat
            def fake_stat(path, *args, **kwargs):
                if str(path) == '/var/run/docker.sock':
                    return SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=0)
                return original_stat(path, *args, **kwargs)
            with patch.dict(os.environ, {'CIRCLECI': 'true'}), patch.object(p, 'host_inventory', return_value={}), patch.object(p.os, 'stat', side_effect=fake_stat), patch.object(p, 'parsed', return_value={}), patch.object(p, 'collect_image', side_effect=result_fn) as calls, contextlib.redirect_stdout(io.StringIO()):
                rc = p.main(['--mode', 'collections-diagnostic', '--allow-pull', '--ephemeral-ci', '--output', str(output)])
            return rc, json.loads(output.read_text()), calls.call_args_list

    def test_diagnostic_plan_uses_four_fresh_containers_and_two_digest_pulls(self):
        def collect(*args, **kwargs):
            return row(kwargs['galaxy_cache'] == 'tmp')
        rc, report, calls = self.run_main_fixture(collect)
        self.assertEqual(rc, 0)
        self.assertEqual(report['status'], 'DIAGNOSTIC_COLLECTED_ONLY')
        self.assertFalse(report['p1_02_complete'])
        self.assertEqual([call.args[0] for call in calls], ['controller', 'controller', 'lint', 'lint'])
        self.assertEqual([call.args[2] for call in calls], [True, False, True, False])
        self.assertTrue(all('@sha256:' in call.args[1] for call in calls))
        self.assertNotIn('target', report['images'])

    def test_image_failure_does_not_start_following_conditions(self):
        def collect(*args, **kwargs):
            return {'status': 'INCOMPLETE', 'cleanup_confirmed': False}
        rc, report, calls = self.run_main_fixture(collect)
        self.assertEqual(rc, 3)
        self.assertEqual(len(calls), 1)
        self.assertEqual(report['error_code'], 'DIAGNOSTIC_COLLECTION_OR_CLEANUP_FAILED')


if __name__ == '__main__':
    unittest.main()
