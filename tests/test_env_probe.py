"""Offline tests: never contact Docker, registries, CI, or Redmine."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('probe', ROOT / 'scripts/p1/env_probe.py')
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)


class Tests(unittest.TestCase):
    def setUp(self):
        self.signals = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}

    def tearDown(self):
        for s, handler in self.signals.items():
            signal.signal(s, handler)

    def test_host_mode_never_calls_docker(self):
        with tempfile.TemporaryDirectory() as d, patch.object(p, 'host_inventory', return_value={'fixture': True}), patch.object(p, 'run', side_effect=AssertionError('external execution')), contextlib.redirect_stdout(io.StringIO()):
            path = Path(d) / 'result.json'
            self.assertEqual(p.main(['--output', str(path)]), 0)
            report = json.loads(path.read_text())
            self.assertEqual(report['images'], {})
            self.assertFalse(report['p1_02_complete'])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_images_require_explicit_ci_scope(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {'CIRCLECI': 'false'}), contextlib.redirect_stderr(io.StringIO()):
            path = Path(d) / 'result.json'
            with self.assertRaises(SystemExit) as exc:
                p.main(['--mode', 'images', '--ephemeral-ci', '--output', str(path)])
            self.assertEqual(exc.exception.code, 2)
            self.assertFalse(path.exists())

    def test_existing_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stderr(io.StringIO()):
            path = Path(d) / 'result.json'
            path.write_text('KEEP')
            with self.assertRaises(SystemExit):
                p.main(['--output', str(path)])
            self.assertEqual(path.read_text(), 'KEEP')

    def test_manifest_config_digest_must_match_local_image(self):
        image_id = 'sha256:' + '1' * 64
        info = {'id': image_id, 'repo_digests': ['example.test/image@sha256:' + '2' * 64]}
        with patch.object(p, 'parsed', return_value={'config': {'digest': 'sha256:' + '3' * 64}}):
            with self.assertRaisesRegex(p.Stop, 'MANIFEST_IMAGE_ID_MISMATCH'):
                p.registry_identity('example.test/image:fixed', info, None)

    def test_index_and_platform_digests_remain_distinct(self):
        a, b, c = ['sha256:' + char * 64 for char in '123']
        info = {'id': c, 'repo_digests': ['example.test/image@' + a]}
        docs = [{'manifests': [{'platform': {'os': 'linux', 'architecture': 'amd64'}, 'digest': b}]}, {'config': {'digest': c}}]
        with patch.object(p, 'parsed', side_effect=docs):
            result = p.registry_identity('example.test/image:fixed', info, None)
        self.assertEqual(result['index_digest'], a)
        self.assertEqual(result['platform_manifest_digest'], b)

    def test_version_mismatch_is_not_success(self):
        result = p.assess('controller', {'arch': 'x86_64', 'python': '3.14.0', 'packages': {'ansible-core': '2.20.0'}, 'collections_status': 'NOT_AVAILABLE'})
        self.assertIn('ansible-core', result['mismatches'])
        self.assertIn('collections', result['unconfirmed'])

    def test_compatible_inventory_does_not_require_missing_module_behavior(self):
        result = p.assess('controller', {'arch': 'x86_64', 'python': '3.14.0', 'packages': p.EXPECTED,
                          'collections_status': 'COLLECTED',
                          'collections': [{'name': n, 'version': v} for n, v in p.COLLECTIONS.items()]})
        self.assertEqual(result, {'mismatches': [], 'unconfirmed': []})

    def test_probe_timeout_cleans_up_and_stays_incomplete(self):
        info = {'id': 'sha256:' + '1' * 64, 'os': 'linux', 'arch': 'amd64'}
        with patch.object(p, 'parsed', side_effect=[info, p.Stop('COMMAND_TIMEOUT')]) as parse, patch.object(p, 'registry_identity', return_value={}), patch.object(p, 'cleanup', return_value=True) as clean:
            row = p.collect_image('target', p.IMAGES['target'], False, 'test', None, 'pass')
        cmd = parse.call_args_list[1].args[0]
        for flag in ['--pull=never', '--read-only', '--cap-drop', '--network', '--pids-limit']:
            self.assertIn(flag, cmd)
        self.assertEqual(cmd[-2], info['id'])
        self.assertNotIn('-v', cmd)
        self.assertEqual(row['status'], 'INCOMPLETE')
        self.assertTrue(row['cleanup_confirmed'])
        clean.assert_called_once_with('ruby-p1-test-target', 'test')

    def test_interrupt_stops_collection_after_cleanup(self):
        info = {'id': 'sha256:' + '1' * 64, 'os': 'linux', 'arch': 'amd64'}
        with patch.object(p, 'parsed', side_effect=[info, p.Stop('INTERRUPTED')]), patch.object(p, 'registry_identity', return_value={}), patch.object(p, 'cleanup', return_value=True) as clean:
            with self.assertRaisesRegex(p.Stop, 'INTERRUPTED'):
                p.collect_image('target', p.IMAGES['target'], False, 'test', None, 'pass')
            clean.assert_called_once()

    def test_cleanup_rejects_unexpected_container_id(self):
        with patch.object(p, 'run', return_value='not-an-id') as run:
            self.assertFalse(p.cleanup('own-name', 'own-run'))
            self.assertEqual(run.call_count, 1)

    def test_raw_error_is_not_exposed(self):
        result = subprocess.CompletedProcess(['example'], 1, '', 'credential=DO_NOT_PERSIST')
        with patch.object(p.subprocess, 'run', return_value=result):
            with self.assertRaises(p.Stop) as exc:
                p.run(['example'])
        self.assertEqual(str(exc.exception), 'COMMAND_EXIT_1')

    def test_json_array_is_rejected_before_use_as_inventory(self):
        for output in ['[]', 'null', '"unexpected"', '4']:
            with self.subTest(output=output), patch.object(p, 'run', return_value=output):
                with self.assertRaisesRegex(p.Stop, '^INVALID_JSON_OBJECT$'):
                    p.parsed(['fixture'])

    def test_invalid_nested_inventory_remains_incomplete_and_cleans_up(self):
        info = {'id': 'sha256:' + '1' * 64, 'os': 'linux', 'arch': 'amd64'}
        probe = {'arch': 'x86_64', 'python': '3.14.0', 'packages': []}
        with patch.object(p, 'parsed', side_effect=[info, probe]), patch.object(p, 'registry_identity', return_value={}), patch.object(p, 'cleanup', return_value=True) as clean:
            row = p.collect_image('controller', p.IMAGES['controller'], False, 'test', None, 'pass')
        self.assertEqual(row['status'], 'INCOMPLETE')
        self.assertEqual(row['error_code'], 'INVALID_PROBE_SCHEMA')
        self.assertTrue(row['cleanup_confirmed'])
        clean.assert_called_once_with('ruby-p1-test-controller', 'test')


if __name__ == '__main__':
    unittest.main()
