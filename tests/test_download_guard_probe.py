"""Real loopback sockets and TLS plus fail-closed CI evidence checks."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import stat
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1] / 'scripts/p1'


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture, host = load('download_guard_fixture'), load('download_guard_probe')
SOURCE = (ROOT / 'source_container_probe.py').read_text()
BUILD = (ROOT / 'build_container_probe.py').read_text()


class LiveTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert, cls.key = fixture.certificate_material()
        cls.report = fixture.exercise(SOURCE, BUILD, cls.cert, cls.key)

    def test_actual_tls_matrix(self):
        self.assertEqual(self.report['status'], fixture.SUCCESS)
        self.assertEqual(len(self.report['cases']), 32)
        self.assertTrue(self.report['temporary_directory_removed'])
        for row in self.report['cases']:
            with self.subTest(row=row):
                self.assertEqual(row['audit_calls'], int(row['case'] == 'valid'))
                self.assertEqual(row['sink_delta'], {x: {'connections': 0, 'requests': 0} for x in ('http', 'https')})

    def test_checksum_guard_removal_is_detected(self):
        old = "if actual != expected:\n        raise Stop('SHA256_MISMATCH')"
        self.assertIn(old, SOURCE)
        changed = SOURCE.replace(old, 'if False:\n        pass', 1)
        with self.assertRaisesRegex(fixture.Stop, '^WRONG_STOP_REASON$'):
            fixture.exercise(changed, BUILD, self.cert, self.key)

    def test_real_forbidden_sink_request_is_detected(self):
        old = "            raise Stop('REDIRECT_NOT_FOLLOWED')"
        injected = """            if response.getheader('Location').startswith('http:'):
                target = urlsplit(response.getheader('Location'))
                client = __import__('http.client', fromlist=['HTTPConnection']).HTTPConnection(target.hostname, target.port, timeout=3)
                client.request('GET', target.path)
                client.getresponse().read()
                client.close()
            raise Stop('REDIRECT_NOT_FOLLOWED')"""
        self.assertIn(old, SOURCE)
        with self.assertRaisesRegex(fixture.Stop, '^REDIRECT_TARGET_CONTACTED$'):
            fixture.exercise(SOURCE.replace(old, injected, 1), BUILD, self.cert, self.key)

    def test_schema_requires_complete_exact_matrix(self):
        good = copy.deepcopy(self.report)
        # Validate the target schema separately; this is not a CS9 execution claim.
        good['python'] = '3.9.19'
        good['platform'] = {'os': 'centos-stream-9', 'arch': 'x86_64', 'uid': 65534}
        host.validate(good)
        for mutation in ('case_missing', 'case_reordered', 'sink_contact', 'boolean_counter',
                         'role_claim', 'secret_field', 'wrong_python', 'nan_time'):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(good)
                if mutation == 'case_missing': bad['cases'].pop()
                if mutation == 'case_reordered': bad['cases'].reverse()
                if mutation == 'sink_contact': bad['cases'][2]['sink_delta']['http']['connections'] = 1
                if mutation == 'boolean_counter': bad['cases'][0]['audit_calls'] = True
                if mutation == 'role_claim': bad['role_verified'] = True
                if mutation == 'secret_field': bad['private_key'] = 'not-a-key'
                if mutation == 'wrong_python': bad['python'] = '3.12.0'
                if mutation == 'nan_time': bad['elapsed_seconds'] = float('nan')
                with self.assertRaises(host.Stop): host.validate(bad)

    def test_evidence_does_not_contain_tls_material(self):
        data = json.dumps(self.report)
        self.assertNotIn(self.key, data)
        self.assertNotIn('PRIVATE KEY', data)
        self.assertNotIn('BEGIN CERTIFICATE', data)


class HostBoundary(unittest.TestCase):
    def test_offline_unprivileged_container(self):
        args = host.arguments(load('target_probe'), 'test-name', 'test-run')
        for flag, value in (('--network', 'none'), ('--user', '65534:65534'),
                            ('--cap-drop', 'ALL'), ('--memory', '512m')):
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertIn('--read-only', args)
        self.assertIn('/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777', args)
        self.assertNotIn('--privileged', args)
        self.assertNotIn('--volume', args)

    def test_payload_hashes_and_syntax(self):
        source = host.payload('test-certificate', 'test-key')
        compile(source, '<fixture-payload>', 'exec')
        self.assertIn('WORKER_ISOLATION', source)
        self.assertNotIn('certificate_material()', source.split('try:\n')[-1])

    def test_failure_output_does_not_escape(self):
        for expected, result in (
            ('WORKER_WORKER_PLATFORM', subprocess.CompletedProcess([], 3, '{"status":"INCOMPLETE","reason":"WORKER_PLATFORM"}', '')),
            ('WORKER_FAILURE_SCHEMA', subprocess.CompletedProcess([], 3, '{"status":"INCOMPLETE","reason":"raw-secret"}', '')),
            ('WORKER_OUTPUT_INVALID', subprocess.CompletedProcess([], 0, '{}', 'raw-secret')),
            ('WORKER_JSON_INVALID', subprocess.CompletedProcess([], 0, 'raw-secret', '')),
        ):
            with self.subTest(result=result), patch.object(host.subprocess, 'run', return_value=result):
                with self.assertRaises(host.Stop) as caught:
                    host.run_worker(['unused'], 'unused', time.monotonic() + 10)
                self.assertEqual(str(caught.exception), expected)
                self.assertNotIn('raw-secret', str(caught.exception))

    def test_unapproved_environment_stops_before_docker(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(host.os.environ, {}, clear=True), \
                patch.object(host.subprocess, 'run') as run:
            output = Path(directory) / 'result.json'
            rc = host.main(['--output', str(output)])
            self.assertEqual(rc, 3)
            self.assertEqual(json.loads(output.read_text())['reason'], 'EXPLICIT_EPHEMERAL_CI_REQUIRED')
            run.assert_not_called()

    def test_worker_timeout_cleans_only_the_owned_container(self):
        target = load('target_probe')
        target.command = Mock(return_value='')
        target.inspect_image = Mock(return_value={})
        target.cleanup = Mock(return_value=True)
        inventory = SimpleNamespace(now=lambda: '2026-11-17T00:00:00Z',
                                    registry_identity=lambda *_: {
                                        'platform_manifest_digest': target.MANIFEST,
                                        'config_digest': target.CONFIG})
        cert_fixture = SimpleNamespace(certificate_material=lambda: ('fixture-cert', 'fixture-key'))
        modules = {'target_probe': target, 'env_probe': inventory, 'download_guard_fixture': cert_fixture}
        original_stat = host.os.stat

        def fixture_stat(path, *args, **kwargs):
            if str(path) == '/var/run/docker.sock':
                return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0)
            return original_stat(path, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(host.os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': host.BRANCH,
                                             'CIRCLE_SHA1': 'e' * 40}, clear=True), \
                patch.object(host.os, 'stat', side_effect=fixture_stat), \
                patch.object(host, 'load', side_effect=modules.__getitem__), \
                patch.object(host, 'payload', return_value='fixture-program'), \
                patch.object(host, 'run_worker', side_effect=host.Stop('WORKER_TIMEOUT')):
            output = Path(directory) / 'result.json'
            rc = host.main(['--output', str(output), '--allow-pull', '--ephemeral-ci', '--allow-live-tls-fixture'])
            saved = json.loads(output.read_text())
            self.assertEqual(rc, 3)
            self.assertEqual(saved['status'], 'INCOMPLETE')
            self.assertEqual(saved['reason'], 'WORKER_TIMEOUT')
            self.assertEqual(saved['cleanup'], {'container_removed': True})
            target.cleanup.assert_called_once_with('ruby-p1-' + saved['run_id'] + '-download-r44', saved['run_id'])
            self.assertNotIn('fixture-key', output.read_text())


if __name__ == '__main__':
    unittest.main()
