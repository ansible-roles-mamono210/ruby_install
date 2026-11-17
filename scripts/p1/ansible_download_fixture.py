"""Bounded stdin protocol for real loopback TLS endpoints in the target."""
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import ssl
import sys
import tempfile

import download_guard_fixture as tls

MATRIX = [('valid', 200, None), ('checksum_mismatch', 200, None)]
MATRIX += [(scheme + '_redirect', status, scheme)
           for scheme in ('http', 'https') for status in tls.REDIRECTS]
MATRIX += [('untrusted_certificate', 200, None), ('hostname_mismatch', 200, None)]


def read():
    raw = sys.stdin.buffer.readline(32769)
    tls.need(raw.endswith(b'\n') and len(raw) <= 32768, 'REQUEST')
    return json.loads(raw)


def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def expect(value):
    tls.need(json.dumps(read(), sort_keys=True) == json.dumps(value, sort_keys=True), 'ORDER')


def serve():
    initial = read()
    tls.need(type(initial) is dict and set(initial) == {'certificate', 'key'}, 'INITIAL_REQUEST')
    tls.need(all(type(v) is str and len(v) < 8192 for v in initial.values()), 'TLS_MATERIAL')
    tls.need(all(x[4][0] in ('127.0.0.1', '::1') for x in socket.getaddrinfo('localhost', None)), 'LOOPBACK')
    if os.environ.get('RUBY_P1_ANSIBLE_TARGET') == 'r49':
        tls.need(platform.python_version() == '3.9.19' and platform.machine() == 'x86_64'
                 and os.geteuid() == 65534 and {n for _, n in socket.if_nameindex()} == {'lo'}
                 and os.statvfs('/').f_flag & os.ST_RDONLY
                 and os.statvfs('/tmp').f_flag & os.ST_NOEXEC, 'TARGET_BASELINE')
        release = Path('/etc/os-release').read_text()
        tls.need('ID="centos"' in release and 'VERSION_ID="9"' in release, 'TARGET_OS')
    body = tls.archive_bytes()
    actual_sha = hashlib.sha256(body).hexdigest()
    with tempfile.TemporaryDirectory(prefix='ruby-p1-ansible-', dir='/tmp') as directory:
        root = Path(directory)
        for name, value in (('cert.pem', initial['certificate']), ('key.pem', initial['key'])):
            fd = os.open(str(root / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(value)
        initial.clear()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(root / 'cert.pem'), str(root / 'key.pem'))
        trusted = ssl.create_default_context(cafile=str(root / 'cert.pem'))
        with tls.serving(context) as origin, tls.serving() as http_sink, tls.serving(context) as https_sink:
            tls.need(tls.barrier(http_sink) == (1, 1)
                     and tls.barrier(https_sink, trusted) == (1, 1), 'CONTROL')
            emit({'state': 'READY', 'python': platform.python_version(),
                  'uid': os.geteuid(), 'cases': len(MATRIX)})
            for index, (case, status, scheme) in enumerate(MATRIX):
                expect({'op': 'prepare', 'index': index})
                case_root = root / ('case-' + str(index))
                case_root.mkdir(mode=0o700)
                destination = case_root / 'source.tar.gz'
                sink = http_sink if scheme == 'http' else https_sink
                location = scheme + '://localhost:' + str(sink.server_port) + '/forbidden' if scheme else None
                origin.reply = (status, location, body if status == 200 else b'')
                before = {'http': tls.barrier(http_sink), 'https': tls.barrier(https_sink, trusted)}
                source_before = origin.accepted, origin.requests
                expected_sha = '0' * 64 if case == 'checksum_mismatch' else actual_sha
                host = '127.0.0.1' if case == 'hostname_mismatch' else 'localhost'
                variables = {'p1_url': 'https://' + host + ':' + str(origin.server_port) + '/source',
                             'p1_destination': str(destination), 'p1_sha256': expected_sha,
                             'p1_ca': '' if case == 'untrusted_certificate' else str(root / 'cert.pem')}
                emit({'state': 'PREPARED', 'index': index, 'variables': variables})
                expect({'op': 'finish', 'index': index})
                after = {'http': tls.barrier(http_sink), 'https': tls.barrier(https_sink, trusted)}
                deltas = {key: {'connections': after[key][0] - before[key][0] - 1,
                                'requests': after[key][1] - before[key][1] - 1} for key in before}
                exists = destination.is_file() and not destination.is_symlink()
                checksum_matches = exists and hashlib.sha256(destination.read_bytes()).hexdigest() == expected_sha
                marker = Path(str(destination) + '.accepted')
                accepted = marker.is_file() and not marker.is_symlink()
                if accepted:
                    tls.need(marker.read_bytes() == b'checksum-verified\n', 'MARKER')
                emit({'state': 'OBSERVED', 'index': index, 'case': case,
                      'response_status': status, 'sink_delta': deltas,
                      'origin_connections': origin.accepted - source_before[0],
                      'origin_requests': origin.requests - source_before[1],
                      'file_exists': exists, 'checksum_matches': checksum_matches,
                      'gate_marker': accepted})
            expect({'op': 'stop'})
    tls.need(not root.exists(), 'TEMPORARY_DIRECTORY_REMAINS')
    emit({'state': 'FINISHED', 'temporary_directory_removed': True})


if __name__ == '__main__':
    try:
        serve()
    except BaseException:
        # Never print raw errors, request bodies or TLS material.
        emit({'state': 'INCOMPLETE', 'reason': 'FIXTURE_PROTOCOL_OR_CHECK'})
        raise SystemExit(3)
