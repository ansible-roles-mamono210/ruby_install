"""Live loopback TLS tests of the unchanged P1 acquisition functions.

Only the endpoint, trusted test CA and expected fixture checksum are adapted.
No mocked HTTP responses, extraction, build, package installation or Role run.
"""
import contextlib
import hashlib
import http.client
import http.server
import io
import json
import os
from pathlib import Path
import platform
import socket
import ssl
import subprocess
import tarfile
import tempfile
import threading
import time
import types

SCHEMA = 'ruby-p1-download-guard-fixture-r44'
SUCCESS = 'LIVE_TLS_ACQUISITION_GUARDS_VERIFIED'
REDIRECTS = (300, 301, 302, 303, 307, 308)
REASONS = ('TLS_CERTIFICATE_GENERATION_FAILED', 'TLS_MATERIAL_TOO_LARGE',
           'FIXTURE_THREAD_NOT_STOPPED', 'SINK_CONTROL_FAILED',
           'UNEXPECTED_SOURCE_DESTINATION', 'TLS_POLICY_CHANGED', 'LOCALHOST_NOT_LOOPBACK',
           'SINK_INITIAL_CONTROL_FAILED', 'WRONG_STOP_REASON', 'WRONG_ACQUISITION_ORDER',
           'REDIRECT_TARGET_CONTACTED', 'VALID_CONTROL_FAILED', 'TLS_TEMPORARY_DIRECTORY_REMAINS',
           'WORKER_IDENTITY', 'WORKER_PLATFORM', 'WORKER_OS', 'WORKER_ISOLATION')


class Stop(Exception):
    pass


def need(value, reason):
    if not value:
        raise Stop(reason)


def certificate_material():
    """Generate a disposable test identity; never print or persist its key."""
    with tempfile.TemporaryDirectory(prefix='ruby-p1-tls-') as tmp:
        root = Path(tmp)
        result = subprocess.run([
            '/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256',
            '-nodes', '-days', '1', '-subj', '/CN=localhost',
            '-addext', 'subjectAltName=DNS:localhost',
            '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'),
        ], capture_output=True, timeout=15, check=False)
        need(result.returncode == 0, 'TLS_CERTIFICATE_GENERATION_FAILED')
        key = (root / 'key.pem').read_text()
        cert = (root / 'cert.pem').read_text()
        need(len(key) < 8192 and len(cert) < 8192, 'TLS_MATERIAL_TOO_LARGE')
        return cert, key


def archive_bytes():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz', format=tarfile.USTAR_FORMAT) as archive:
        root = tarfile.TarInfo('ruby-3.4.12')
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        archive.addfile(root)
        for name in ('configure', 'configure.ac', 'version.h'):
            data = b'fixture only; never execute\n'
            entry = tarfile.TarInfo('ruby-3.4.12/' + name)
            entry.size, entry.mode = len(data), 0o644
            archive.addfile(entry, io.BytesIO(data))
    return output.getvalue()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.requests += 1
        if self.path == '/barrier':
            status, location, body = 200, None, b'barrier'
        else:
            status, location, body = self.server.reply
        self.send_response(status)
        if location is not None:
            self.send_header('Location', location)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


class Server(http.server.HTTPServer):
    def __init__(self, tls=None):
        self.tls = tls
        self.accepted = self.requests = 0
        self.reply = (200, None, b'sink')
        super().__init__(('127.0.0.1', 0), Handler)

    def get_request(self):
        sock, address = super().get_request()
        self.accepted += 1
        sock.settimeout(3)
        if self.tls:
            try:
                sock = self.tls.wrap_socket(sock, server_side=True)
            except BaseException:
                sock.close()
                raise
        return sock, address

    def handle_error(self, *_):
        # Fixture logs contain fixed counters, never raw HTTP or TLS exceptions.
        pass


@contextlib.contextmanager
def serving(tls=None):
    server = Server(tls)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=4)
        need(not thread.is_alive(), 'FIXTURE_THREAD_NOT_STOPPED')


def barrier(server, context=None):
    cls = http.client.HTTPSConnection if context else http.client.HTTPConnection
    kwargs = {'context': context} if context else {}
    client = cls('localhost', server.server_port, timeout=3, **kwargs)
    try:
        client.request('GET', '/barrier')
        response = client.getresponse()
        need(response.status == 200 and response.read(16) == b'barrier', 'SINK_CONTROL_FAILED')
    finally:
        client.close()
    return server.accepted, server.requests


def fixture_modules(source_text, build_text, checksum, server, context, hostname='localhost'):
    source, build = types.ModuleType('r44_source'), types.ModuleType('r44_build')
    exec(compile(source_text, '<unchanged-source-worker>', 'exec'), source.__dict__)
    exec(compile(build_text, '<unchanged-build-worker>', 'exec'), build.__dict__)
    source.SOURCES = ((build.VERSION, build.SOURCE_PATH, checksum),)
    build.SOURCE_SHA = checksum
    counts = {'connections': 0, 'audit': 0}

    def connect(host, port=443, timeout=30, context=None):
        need(host == 'cache.ruby-lang.org' and port == 443, 'UNEXPECTED_SOURCE_DESTINATION')
        need(context is client_context and context.check_hostname
             and context.verify_mode == ssl.CERT_REQUIRED, 'TLS_POLICY_CHANGED')
        counts['connections'] += 1
        return http.client.HTTPSConnection(hostname, server.server_port, timeout=3, context=context)

    client_context = context
    tls_adapter = types.SimpleNamespace(create_default_context=lambda: context, CERT_REQUIRED=ssl.CERT_REQUIRED)
    transport = types.SimpleNamespace(client=types.SimpleNamespace(HTTPSConnection=connect))
    source.ssl = build.ssl = tls_adapter
    source.http = build.http = transport
    real_audit = source.audit_archive

    def audit(*args, **kwargs):
        counts['audit'] += 1
        return real_audit(*args, **kwargs)

    source.audit_archive = audit
    return source, build, counts


def exercise(source_text, build_text, cert, key):
    start = time.monotonic()
    need(all(x[4][0] in ('127.0.0.1', '::1') for x in socket.getaddrinfo('localhost', None)),
         'LOCALHOST_NOT_LOOPBACK')
    body = archive_bytes()
    checksum = hashlib.sha256(body).hexdigest()
    rows = []
    with tempfile.TemporaryDirectory(prefix='ruby-p1-live-tls-') as tmp:
        root = Path(tmp)
        for name, text in (('cert.pem', cert), ('key.pem', key)):
            fd = os.open(str(root / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as handle:
                handle.write(text)
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(str(root / 'cert.pem'), str(root / 'key.pem'))
        trusted = ssl.create_default_context(cafile=str(root / 'cert.pem'))
        with serving(server_tls) as origin, serving() as http_sink, serving(server_tls) as https_sink:
            controls = {'http': barrier(http_sink), 'https': barrier(https_sink, trusted)}
            need(controls == {'http': (1, 1), 'https': (1, 1)}, 'SINK_INITIAL_CONTROL_FAILED')
            for kind in ('source', 'build'):
                cases = [('valid', 200, None), ('checksum_mismatch', 200, None)]
                cases += [(scheme + '_redirect', status, scheme)
                          for scheme in ('http', 'https') for status in REDIRECTS]
                cases += [('untrusted_certificate', 200, None), ('hostname_mismatch', 200, None)]
                for case, status, scheme in cases:
                    expected = ('SHA256_MISMATCH' if case == 'checksum_mismatch' else
                                'REDIRECT_NOT_FOLLOWED' if scheme and kind == 'source' else
                                'SOURCE_HTTP_STATUS_OR_REDIRECT' if scheme else
                                'TLS_CERTIFICATE_REJECTED' if case in ('untrusted_certificate', 'hostname_mismatch')
                                else 'ACCEPTED')
                    context = ssl.create_default_context() if case == 'untrusted_certificate' else trusted
                    hostname = '127.0.0.1' if case == 'hostname_mismatch' else 'localhost'
                    expected_sha = '0' * 64 if case == 'checksum_mismatch' else checksum
                    source, build, counts = fixture_modules(source_text, build_text, expected_sha, origin, context, hostname)
                    sink = http_sink if scheme == 'http' else https_sink
                    location = (scheme + '://localhost:' + str(sink.server_port) + '/forbidden') if scheme else None
                    origin.reply = (status, location, body if status == 200 else b'')
                    before = {'http': barrier(http_sink), 'https': barrier(https_sink, trusted)}
                    row = {}
                    with tempfile.TemporaryDirectory(prefix='download-', dir=root) as directory:
                        try:
                            if kind == 'source':
                                source.download(source.SOURCES[0], row)
                            else:
                                build.download(source, directory, row)
                            outcome = 'ACCEPTED'
                        except (source.Stop, build.Stop) as error:
                            outcome = str(error)
                        except ssl.SSLCertVerificationError:
                            outcome = 'TLS_CERTIFICATE_REJECTED'
                    after = {'http': barrier(http_sink), 'https': barrier(https_sink, trusted)}
                    deltas = {name: {'connections': after[name][0] - before[name][0] - 1,
                                     'requests': after[name][1] - before[name][1] - 1}
                              for name in ('http', 'https')}
                    need(outcome == expected, 'WRONG_STOP_REASON')
                    need(counts == {'connections': 1, 'audit': int(case == 'valid')}, 'WRONG_ACQUISITION_ORDER')
                    need(all(value == 0 for sink_counts in deltas.values() for value in sink_counts.values()),
                         'REDIRECT_TARGET_CONTACTED')
                    if case == 'valid':
                        need(row['checksum_match'] is True and row['sha256'] == checksum
                             and row['archive']['status'] == 'PASSED', 'VALID_CONTROL_FAILED')
                    rows.append({'helper': kind, 'case': case, 'response_status': status,
                                 'outcome': outcome, 'audit_calls': counts['audit'],
                                 'connection_factory_calls': counts['connections'], 'sink_delta': deltas})
    need(not root.exists(), 'TLS_TEMPORARY_DIRECTORY_REMAINS')
    return {'schema': SCHEMA, 'status': SUCCESS, 'python': platform.python_version(),
            'scope': 'unchanged_p1_download_functions_with_fixture_endpoint_ca_and_checksum',
            'tls_certificate_and_hostname_checks': True, 'sink_positive_controls': True,
            'temporary_directory_removed': True, 'redirect_policy': 'reject_all_candidate_only',
            'role_verified': False, 'full_build_entrypoint_executed': False,
            'p1_04_complete': False, 'phase1_complete': False,
            'cases': rows, 'elapsed_seconds': round(time.monotonic() - start, 3)}
