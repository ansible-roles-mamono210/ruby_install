"""Offline source-acquisition boundary tests. No Docker or external network."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import stat
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/p1' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


w, h, runtime = load('source_container_probe'), load('source_probe'), load('runtime_smoke')


class Response(io.BytesIO):
    def __init__(self, body=b'test source bytes', status=200, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = {} if headers is None else headers

    def getheader(self, key, default=None):
        return self.headers.get(key, default)


def report():
    return {'schema': 'ruby-p1-source-container-r17', 'status': w.SUCCESS,
            'scope': 'two_fixed_https_urls_no_extraction', 'python': '3.9.19',
            'redirect_policy': 'reject_all_for_measurement_only',
            'redirect_fixture_tested': False, 'ansible_download_verified': False,
            'archive_safety_verified': False, 'build_verified': False,
            'results': [{'version': v, 'url': 'https://' + w.HOST + p, 'expected_sha256': d,
                         'http_status': 200, 'redirect': 'none', 'bytes': 100,
                         'sha256': d, 'checksum_match': True, 'elapsed_seconds': 0.5,
                         'temporary_file_removed': True} for v, p, d in w.SOURCES]}


class BodyTests(unittest.TestCase):
    def receive(self, body=b'test source bytes', headers=None, expected=None, deadline=None):
        expected = expected or hashlib.sha256(body).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            dest = Path(directory) / 'source'
            value = w.receive(Response(body, headers=headers), dest, expected,
                              time.monotonic() + 30 if deadline is None else deadline)
            self.assertEqual(dest.read_bytes(), body)
            return value

    def test_valid_content_length(self):
        self.assertEqual(self.receive(headers={'Content-Length': '17'})['bytes'], 17)

    def test_missing_content_length(self):
        self.assertTrue(self.receive()['checksum_match'])

    def test_empty_body(self):
        with self.assertRaisesRegex(w.Stop, 'BODY_LENGTH_MISMATCH'):
            self.receive(body=b'')

    def test_truncated_body(self):
        with self.assertRaisesRegex(w.Stop, 'BODY_LENGTH_MISMATCH'):
            self.receive(headers={'Content-Length': '999'})

    def test_bad_content_lengths(self):
        for length in ('-1', '0', 'SECRET', '17, 17', str(w.MAX_BYTES + 1)):
            with self.subTest(length=length), self.assertRaisesRegex(w.Stop, 'CONTENT_LENGTH_INVALID'):
                self.receive(headers={'Content-Length': length})

    def test_content_encoding_refused(self):
        with self.assertRaisesRegex(w.Stop, 'CONTENT_ENCODING_UNEXPECTED'):
            self.receive(headers={'Content-Encoding': 'gzip'})

    def test_checksum_mismatch(self):
        with self.assertRaisesRegex(w.Stop, 'SHA256_MISMATCH'):
            self.receive(expected='0' * 64)

    def test_size_bound_without_length(self):
        with patch.object(w, 'MAX_BYTES', 8), self.assertRaisesRegex(w.Stop, 'DOWNLOAD_TOO_LARGE'):
            self.receive()

    def test_deadline(self):
        with self.assertRaisesRegex(w.Stop, 'DOWNLOAD_TIME_LIMIT'):
            self.receive(deadline=0)

    def test_existing_file_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            dest = Path(directory) / 'old'
            dest.write_bytes(b'preserved')
            with self.assertRaises(FileExistsError):
                w.receive(Response(), dest, '0' * 64, time.monotonic() + 30)
            self.assertEqual(dest.read_bytes(), b'preserved')


class DownloadTests(unittest.TestCase):
    def test_redirects_stop_before_second_request(self):
        for code in (300, 301, 302, 303, 307, 308):
            for location in ('http://example.invalid/SECRET', 'https://example.invalid/SECRET', '/SECRET'):
                conn = Mock()
                conn.getresponse.return_value = Response(status=code, headers={'Location': location})
                with self.subTest(code=code, location=location), \
                        patch.object(w.http.client, 'HTTPSConnection', return_value=conn) as create, \
                        patch.object(w, 'receive') as receive:
                    row = {}
                    with self.assertRaisesRegex(w.Stop, 'REDIRECT_NOT_FOLLOWED'):
                        w.download(w.SOURCES[0], row)
                    self.assertEqual(create.call_count, 1)
                    self.assertEqual(conn.request.call_count, 1)
                    receive.assert_not_called()
                    conn.close.assert_called_once()
                    self.assertNotIn('SECRET', json.dumps(row))

    def test_non_200_stops(self):
        for status in (206, 403, 404, 500):
            conn = Mock()
            conn.getresponse.return_value = Response(status=status)
            with patch.object(w.http.client, 'HTTPSConnection', return_value=conn), \
                    self.assertRaisesRegex(w.Stop, 'HTTP_STATUS_UNEXPECTED'):
                w.download(w.SOURCES[0], {})

    def test_no_arbitrary_url(self):
        with patch.object(w.http.client, 'HTTPSConnection') as create, \
                self.assertRaisesRegex(w.Stop, 'SOURCE_NOT_ALLOWED'):
            w.download(('x', 'http://example.invalid', '0' * 64), {})
        create.assert_not_called()

    def test_success_uses_verified_tls_and_cleans_temp_file(self):
        conn = Mock()
        conn.getresponse.return_value = Response()
        paths = []

        def receive(response, path, checksum, deadline):
            paths.append(path)
            path.write_bytes(b'measured')
            self.assertEqual(checksum, w.SOURCES[0][2])
            return {'sha256': checksum, 'bytes': 8, 'checksum_match': True}

        with patch.object(w.http.client, 'HTTPSConnection', return_value=conn) as create, \
                patch.object(w, 'receive', side_effect=receive):
            row = {}
            w.download(w.SOURCES[0], row)
        ctx = create.call_args.kwargs['context']
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(create.call_args.args, (w.HOST,))
        self.assertEqual(create.call_args.kwargs['port'], 443)
        self.assertEqual(conn.request.call_args.args, ('GET', w.SOURCES[0][1]))
        self.assertTrue(all(not p.exists() for p in paths))
        self.assertTrue(row['temporary_file_removed'])

    def test_checksum_failure_cleans_temp_file(self):
        conn = Mock()
        conn.getresponse.return_value = Response()
        paths = []

        def fail(response, path, checksum, deadline):
            paths.append(path)
            path.write_bytes(b'partial')
            raise w.Stop('SHA256_MISMATCH')

        with patch.object(w.http.client, 'HTTPSConnection', return_value=conn), \
                patch.object(w, 'receive', side_effect=fail), \
                self.assertRaisesRegex(w.Stop, 'SHA256_MISMATCH'):
            w.download(w.SOURCES[0], {})
        self.assertTrue(all(not p.exists() for p in paths))

    def worker_main(self, env=None, error=None):
        out = io.StringIO()
        with patch.dict(os.environ, {'RUBY_P1_SOURCE_PROBE': '1', **(env or {})}, clear=True), \
                patch.object(w.os, 'geteuid', return_value=65534), \
                patch.object(w.platform, 'python_version', return_value='3.9.19'), \
                patch.object(w.platform, 'machine', return_value='x86_64'), \
                patch.object(w, 'download', side_effect=error) as download, contextlib.redirect_stdout(out):
            rc = w.main()
        return rc, json.loads(out.getvalue()), download

    def test_network_override_refused_before_request(self):
        for key in ('http_proxy', 'HTTPS_PROXY', 'SSLKEYLOGFILE', 'SSL_CERT_FILE'):
            rc, value, download = self.worker_main({key: 'SECRET'})
            self.assertEqual(rc, 3)
            self.assertEqual(value['reason'], 'NETWORK_OR_TLS_OVERRIDE_PRESENT')
            download.assert_not_called()
            self.assertNotIn('SECRET', json.dumps(value))

    def test_network_error_does_not_retry_or_log_secret(self):
        rc, value, download = self.worker_main(error=OSError('SECRET'))
        self.assertEqual(rc, 3)
        self.assertEqual(download.call_count, 1)
        self.assertEqual(value['reason'], 'NETWORK_OR_IO_ERROR')
        self.assertNotIn('SECRET', json.dumps(value))

    def test_tls_certificate_failure_is_distinct(self):
        rc, value, download = self.worker_main(error=ssl.SSLCertVerificationError('SECRET'))
        self.assertEqual(value['reason'], 'TLS_CERTIFICATE_VERIFICATION_FAILED')
        self.assertEqual(download.call_count, 1)
        self.assertEqual(rc, 3)


class HostTests(unittest.TestCase):
    def test_success_schema(self):
        h.validate(report(), w)

    def test_report_rejects_missing_extra_reordered_and_false_claims(self):
        bad = []
        item = report(); item['results'].pop(); bad.append(item)
        item = report(); item['results'].reverse(); bad.append(item)
        item = report(); item['SECRET'] = 'SECRET'; bad.append(item)
        item = report(); item['build_verified'] = True; bad.append(item)
        for field, value in (('sha256', '0' * 64), ('bytes', True), ('http_status', True),
                             ('temporary_file_removed', False), ('elapsed_seconds', float('nan')),
                             ('url', 'http://example.invalid'), ('redirect', 'https')):
            item = report(); item['results'][0][field] = value; bad.append(item)
        for item in bad:
            with self.subTest(item=item), self.assertRaises(h.Stop):
                h.validate(item, w)

    def test_failure_summary_omits_unapproved_fields(self):
        value = {'reason': 'SHA256_MISMATCH', 'SECRET': 'SECRET', 'results': [
            {'version': '3.4.12', 'http_status': 200, 'redirect': 'none', 'url': 'SECRET', 'body': 'SECRET'}]}
        result = h.failure_summary(value)
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertEqual(result['reason'], 'SHA256_MISMATCH')

    def test_container_boundaries(self):
        args = h.arguments(runtime, 'test', 'identity')
        for value in ('--read-only', '--cap-drop', 'ALL', 'no-new-privileges', '65534:65534',
                      '512m', '/tmp:rw,nosuid,nodev,noexec,size=96m,mode=1777'):
            self.assertIn(value, args)
        for value in ('--mount', '--volume', '-v', '--privileged', '--publish'):
            self.assertNotIn(value, args)
        self.assertEqual(args[args.index('--network') + 1], 'bridge')
        self.assertEqual(args[-4:], [runtime.TARGET_CONFIG, '-I', '-B', '-'])

    def test_no_authorization_creates_no_output(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(h, 'load') as load, \
                patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(io.StringIO()):
            path = Path(directory) / 'report.json'
            self.assertEqual(h.main(['--output', str(path)]), 3)
            self.assertFalse(path.exists())
            load.assert_not_called()

    def run_host(self, value=None, rc=0, stderr='', cleanup=True, timeout=False):
        runtime_mock = SimpleNamespace(**{k: getattr(runtime, k) for k in (
            'DOCKER', 'TARGET', 'TARGET_CONFIG', 'TARGET_MANIFEST')})
        runtime_mock.command = Mock(return_value='')
        runtime_mock.inspect_image = Mock(return_value={})
        runtime_mock.cleanup = Mock(return_value=cleanup)
        inv = SimpleNamespace(now=lambda: '2026-11-14T00:00:00Z', registry_identity=lambda *a: {
            'platform_manifest_digest': runtime.TARGET_MANIFEST, 'config_digest': runtime.TARGET_CONFIG})
        modules = {'runtime_smoke': runtime_mock, 'env_probe': inv, 'source_container_probe': w}
        proc = SimpleNamespace(returncode=rc, stdout=json.dumps(report() if value is None else value), stderr=stderr)
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': h.BRANCH}, clear=True), \
                patch.object(h.platform, 'system', return_value='Linux'), \
                patch.object(h.platform, 'machine', return_value='x86_64'), \
                patch.object(h, 'load', side_effect=modules.__getitem__), \
                patch.object(h.os, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=0)), \
                patch.object(h.subprocess, 'run', return_value=proc,
                             side_effect=subprocess.TimeoutExpired('mock', 1) if timeout else None), \
                contextlib.redirect_stdout(io.StringIO()):
            path = Path(directory) / 'report.json'
            result = h.main(['--output', str(path), '--allow-pull', '--ephemeral-ci', '--allow-source-download'])
            saved = json.loads(path.read_text())
        return result, saved, runtime_mock

    def test_host_success_has_cleanup_and_incomplete_phase_flags(self):
        rc, value, runtime_mock = self.run_host()
        self.assertEqual(rc, 0)
        self.assertEqual(value['status'], w.SUCCESS)
        self.assertFalse(value['p1_03_complete'])
        self.assertFalse(value['phase1_complete'])
        self.assertTrue(value['cleanup_confirmed'])
        runtime_mock.cleanup.assert_called_once()

    def test_cleanup_failure_overrides_success(self):
        rc, value, _ = self.run_host(cleanup=False)
        self.assertEqual((rc, value['status'], value['reason']), (3, 'INCOMPLETE', 'CLEANUP_UNCONFIRMED'))

    def test_worker_timeout_still_cleans(self):
        rc, value, runtime_mock = self.run_host(timeout=True)
        self.assertEqual((rc, value['reason']), (3, 'COMMAND_TIMEOUT'))
        runtime_mock.cleanup.assert_called_once()

    def test_worker_failure_records_bounded_reason(self):
        rc, value, runtime_mock = self.run_host(value={'status': 'INCOMPLETE', 'reason': 'SHA256_MISMATCH',
                                                      'SECRET': 'SECRET'}, rc=3)
        self.assertEqual(rc, 3)
        self.assertEqual(value['failure']['reason'], 'SHA256_MISMATCH')
        self.assertNotIn('SECRET', json.dumps(value))
        runtime_mock.cleanup.assert_called_once()

    def test_stderr_and_exit_fail_closed(self):
        for rc, stderr, reason in ((0, 'SECRET', 'WORKER_OUTPUT_REJECTED'), (3, '', 'WORKER_EXIT_MISMATCH')):
            code, value, _ = self.run_host(rc=rc, stderr=stderr)
            self.assertEqual(code, 3)
            self.assertEqual(value['reason'], reason)
            self.assertNotIn('SECRET', json.dumps(value))

    def test_config_retains_gates_and_single_job(self):
        config = yaml.safe_load((ROOT / '.circleci/config.yml').read_text())
        self.assertFalse(config['parameters']['run_p1_env_probe']['default'])
        workflow = config['workflows']['p1-environment-measurement']
        self.assertEqual(workflow['jobs'], ['p1-environment'])
        self.assertEqual(workflow['when']['and'][1], {'equal': [h.BRANCH, '<< pipeline.git.branch >>']})
        job = config['jobs']['p1-environment']
        self.assertEqual(job['machine']['image'], 'ubuntu-2204:2023.10.1')
        self.assertEqual(job['resource_class'], 'medium')
        command = job['steps'][1]['run']['command']
        self.assertIn('scripts/p1/source_probe.py', command)
        self.assertIn('--allow-source-download', command)
        self.assertNotIn('runtime_smoke.py', command)
        # The runner must not kill the quiet collector before its own timeout
        # and 30-second termination grace can record an outcome.
        no_output_minutes = int(job['steps'][1]['run']['no_output_timeout'].removesuffix('m'))
        self.assertGreater(no_output_minutes * 60, 12 * 60 + 30)


if __name__ == '__main__':
    unittest.main()
