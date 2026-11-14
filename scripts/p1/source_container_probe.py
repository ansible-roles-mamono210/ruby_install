"""Fixed-URL acquisition measurement only. Never extract or execute downloads."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import ssl
import tempfile
import time
from urllib.parse import urlsplit

HOST = 'cache.ruby-lang.org'
SOURCES = (
    ('3.4.12', '/pub/ruby/3.4/ruby-3.4.12.tar.gz',
     '5e5d85ad93b0adcccbad47733680f4892bd0078e3342437f7babce01c1872479'),
    ('4.0.9', '/pub/ruby/4.0/ruby-4.0.9.tar.gz',
     'c35350682ff050b79702d57ade4516e7336063f510155d19fb2fb5b3f3909511'),
)
MAX_BYTES = 64 * 1024 * 1024
BLOCK = 64 * 1024
SUCCESS = 'SOURCE_DOWNLOADS_AND_SHA256_PASSED'


class Stop(Exception):
    pass


def redirect_class(value):
    if not value:
        return 'missing'
    try:
        if len(value) > 8192 or any(ord(c) < 32 for c in value):
            return 'invalid'
        scheme = urlsplit(value).scheme.lower()
    except ValueError:
        return 'invalid'
    return scheme if scheme in ('http', 'https') else 'other' if scheme else 'relative'


def receive(response, destination, expected, deadline):
    """Hash the exact identity-encoded response body, with bounded disk usage."""
    encoding = response.getheader('Content-Encoding', 'identity').lower()
    if encoding != 'identity':
        raise Stop('CONTENT_ENCODING_UNEXPECTED')
    length = response.getheader('Content-Length')
    if length is not None:
        if not re.fullmatch(r'[0-9]{1,12}', length) or not 0 < int(length) <= MAX_BYTES:
            raise Stop('CONTENT_LENGTH_INVALID')
        length = int(length)
    digest = hashlib.sha256()
    count = 0
    with destination.open('xb') as output:
        while True:
            if time.monotonic() >= deadline:
                raise Stop('DOWNLOAD_TIME_LIMIT')
            block = response.read(min(BLOCK, MAX_BYTES - count + 1))
            if not block:
                break
            count += len(block)
            if count > MAX_BYTES:
                raise Stop('DOWNLOAD_TOO_LARGE')
            digest.update(block)
            output.write(block)
    if count == 0 or (length is not None and count != length):
        raise Stop('BODY_LENGTH_MISMATCH')
    actual = digest.hexdigest()
    if actual != expected:
        raise Stop('SHA256_MISMATCH')
    return {'bytes': count, 'sha256': actual, 'checksum_match': True}


def download(source, row):
    version, path, expected = source
    # No caller-supplied URL, headers, proxy, cookie, credentials, or redirect loop.
    if source not in SOURCES:
        raise Stop('SOURCE_NOT_ALLOWED')
    context = ssl.create_default_context()
    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise Stop('TLS_POLICY_MISMATCH')
    connection = http.client.HTTPSConnection(HOST, port=443, timeout=30, context=context)
    start = time.monotonic()
    try:
        connection.request('GET', path, headers={
            'Accept-Encoding': 'identity', 'User-Agent': 'ruby-p1-source-measurement-r17'})
        response = connection.getresponse()
        row['http_status'] = response.status
        # http.client does not follow redirects. Never request the Location URL.
        if 300 <= response.status <= 399:
            row['redirect'] = redirect_class(response.getheader('Location'))
            raise Stop('REDIRECT_NOT_FOLLOWED')
        if response.status != 200:
            raise Stop('HTTP_STATUS_UNEXPECTED')
        row['redirect'] = 'none'
        with tempfile.TemporaryDirectory(prefix='ruby-p1-source-', dir='/tmp') as directory:
            row.update(receive(response, Path(directory) / 'source.tar.gz', expected, start + 120))
        row['elapsed_seconds'] = round(time.monotonic() - start, 3)
        row['temporary_file_removed'] = True
    finally:
        connection.close()


def main():
    report = {'schema': 'ruby-p1-source-container-r17', 'status': 'INCOMPLETE',
              'scope': 'two_fixed_https_urls_no_extraction', 'results': [],
              'redirect_policy': 'reject_all_for_measurement_only',
              'redirect_fixture_tested': False, 'ansible_download_verified': False,
              'archive_safety_verified': False, 'build_verified': False}
    try:
        if (os.environ.get('RUBY_P1_SOURCE_PROBE') != '1' or os.geteuid() != 65534
                or platform.python_version() != '3.9.19' or platform.machine() != 'x86_64'):
            raise Stop('CONTAINER_IDENTITY_MISMATCH')
        forbidden = ('http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY',
                     'ALL_PROXY', 'SSLKEYLOGFILE', 'SSL_CERT_FILE', 'SSL_CERT_DIR')
        if any(os.environ.get(key) for key in forbidden):
            raise Stop('NETWORK_OR_TLS_OVERRIDE_PRESENT')
        report['python'] = platform.python_version()
        for source in SOURCES:
            version, path, expected = source
            row = {'version': version, 'url': 'https://' + HOST + path, 'expected_sha256': expected}
            report['results'].append(row)
            download(source, row)
        report['status'] = SUCCESS
    except Stop as error:
        report['reason'] = str(error)
    except ssl.SSLCertVerificationError:
        report['reason'] = 'TLS_CERTIFICATE_VERIFICATION_FAILED'
    except (TimeoutError, OSError, http.client.HTTPException):
        report['reason'] = 'NETWORK_OR_IO_ERROR'
    except Exception:
        report['reason'] = 'UNEXPECTED_ERROR'
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == SUCCESS else 3


if __name__ == '__main__':
    raise SystemExit(main())
