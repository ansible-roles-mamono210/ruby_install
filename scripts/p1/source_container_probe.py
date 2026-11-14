"""Fixed-URL acquisition measurement only. Never extract or execute downloads."""
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import ssl
import tempfile
import tarfile
import time
import zlib
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
SUCCESS = 'SOURCE_ARCHIVE_AUDIT_PASSED'
MAX_TAR_BYTES = 384 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_HEADERS = 30000
MAX_PATH = 1024
MAX_METADATA = 64 * 1024
REQUIRED_FILES = ('configure', 'configure.ac', 'version.h')


class Stop(Exception):
    pass


def archive_path(value, root, directory=False):
    if (not value or len(value.encode('utf-8')) > MAX_PATH or '\\' in value
            or any(ord(c) < 32 or ord(c) == 127 for c in value) or value.startswith('/')):
        raise Stop('ARCHIVE_PATH_INVALID')
    if directory and value.endswith('/'):
        value = value[:-1]
    parts = value.split('/')
    if parts[0] != root or any(p in ('', '.', '..') for p in parts):
        raise Stop('ARCHIVE_PATH_INVALID')
    return value


def pax_records(data):
    """Parse bounded PAX records without letting an extension drive file reads."""
    values = {}
    allowed = {'path', 'linkpath', 'size', 'mtime', 'atime', 'ctime', 'uid', 'gid',
               'uname', 'gname', 'comment', 'charset', 'hdrcharset'}
    while data:
        prefix, sep, _ = data.partition(b' ')
        if not sep or not re.fullmatch(rb'[1-9][0-9]{0,5}', prefix):
            raise Stop('ARCHIVE_METADATA_INVALID')
        length = int(prefix)
        if not len(prefix) + 3 <= length <= len(data) or data[length - 1:length] != b'\n':
            raise Stop('ARCHIVE_METADATA_INVALID')
        key, equal, raw = data[len(prefix) + 1:length - 1].partition(b'=')
        if not equal:
            raise Stop('ARCHIVE_METADATA_INVALID')
        key, value = key.decode('utf-8'), raw.decode('utf-8')
        if key not in allowed or key in values:
            raise Stop('ARCHIVE_METADATA_UNSUPPORTED')
        values[key] = value
        data = data[length:]
    return values


class ArchiveReader:
    def __init__(self, stream, deadline):
        self.stream, self.deadline, self.count = stream, deadline, 0

    def read(self, size):
        if not 0 <= size <= BLOCK:
            raise Stop('ARCHIVE_READ_BOUND')
        if time.monotonic() >= self.deadline:
            raise Stop('ARCHIVE_TIME_LIMIT')
        data = self.stream.read(min(size, MAX_TAR_BYTES - self.count + 1))
        self.count += len(data)
        if self.count > MAX_TAR_BYTES:
            raise Stop('ARCHIVE_EXPANSION_LIMIT')
        return data

    def exact(self, size):
        data = self.read(size)
        if len(data) != size:
            raise Stop('ARCHIVE_TRUNCATED')
        return data

    def skip_payload(self, size):
        while size:
            chunk = min(size, BLOCK)
            self.exact(chunk)
            size -= chunk


def check_archive_graph(nodes, root):
    """Reject path collisions and resolve links component by component."""
    directories = {root}
    for name in nodes:
        parts = name.split('/')
        for i in range(1, len(parts)):
            parent = '/'.join(parts[:i])
            if parent in nodes and nodes[parent][0] != 'directory':
                raise Stop('ARCHIVE_PARENT_CONFLICT')
            directories.add(parent)
    for name, (kind, target, _) in nodes.items():
        if kind == 'directory':
            directories.add(name)
        if kind == 'hardlink':
            target = archive_path(target, root)
            if target not in nodes or nodes[target][0] != 'file':
                raise Stop('ARCHIVE_HARDLINK_TARGET')
    for name, (kind, _, _) in nodes.items():
        if kind != 'symlink':
            continue
        pending, resolved, hops = name.split('/'), [], 0
        while pending:
            part = pending.pop(0)
            if part in ('', '.'):
                continue
            if part == '..':
                if len(resolved) <= 1:
                    raise Stop('ARCHIVE_LINK_ESCAPE')
                resolved.pop()
                continue
            resolved.append(part)
            if resolved[0] != root:
                raise Stop('ARCHIVE_LINK_ESCAPE')
            current = '/'.join(resolved)
            node = nodes.get(current)
            if node and node[0] in ('symlink', 'hardlink'):
                hops += 1
                if hops > 40:
                    raise Stop('ARCHIVE_LINK_CYCLE_OR_DEPTH')
                target = node[1]
                if (not target or target.startswith('/') or '\\' in target
                        or len(target.encode('utf-8')) > MAX_PATH
                        or any(ord(c) < 32 or ord(c) == 127 for c in target)):
                    raise Stop('ARCHIVE_LINK_ESCAPE')
                pending = target.split('/') + pending
                resolved = resolved[:-1] if node[0] == 'symlink' else []
            elif pending and current not in directories:
                raise Stop('ARCHIVE_LINK_TARGET')
        target = '/'.join(resolved)
        if target not in nodes and target not in directories:
            raise Stop('ARCHIVE_LINK_TARGET')
    for required in REQUIRED_FILES:
        if nodes.get(root + '/' + required, ('', '', 0))[0] != 'file':
            raise Stop('ARCHIVE_REQUIRED_FILE')
        if nodes[root + '/' + required][2] == 0:
            raise Stop('ARCHIVE_REQUIRED_FILE')


def audit_archive(path, version, deadline):
    """Decompress into bounded memory chunks; never extract a member to disk.

    This deliberately limited measurement reader supports ordinary ustar/GNU
    headers and bounded known PAX metadata. Unsupported metadata fails closed.
    It is not a production extractor or a guarantee about later extraction.
    """
    root, nodes = 'ruby-' + version, {}
    counts = {kind: 0 for kind in ('file', 'directory', 'symlink', 'hardlink')}
    headers, file_bytes, pending, global_pax, chain = 0, 0, {}, {}, 0
    try:
        with gzip.open(path, 'rb') as stream:
            reader = ArchiveReader(stream, deadline)
            while True:
                block = reader.exact(512)
                if block == bytes(512):
                    if pending or chain or reader.exact(512) != bytes(512):
                        raise Stop('ARCHIVE_END_INVALID')
                    # Read through gzip EOF/CRC and reject hidden concatenated tar data.
                    while True:
                        tail = reader.read(BLOCK)
                        if not tail:
                            break
                        if any(tail):
                            raise Stop('ARCHIVE_TRAILING_DATA')
                    if reader.count % 512:
                        raise Stop('ARCHIVE_END_INVALID')
                    break
                headers += 1
                if headers > MAX_HEADERS:
                    raise Stop('ARCHIVE_HEADER_LIMIT')
                member = tarfile.TarInfo.frombuf(block, 'utf-8', 'strict')
                if member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE,
                                   tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
                    chain += 1
                    if chain > 8 or not 0 < member.size <= MAX_METADATA:
                        raise Stop('ARCHIVE_METADATA_LIMIT')
                    data = reader.exact(member.size)
                    if any(reader.exact((-member.size) % 512)):
                        raise Stop('ARCHIVE_PADDING_INVALID')
                    if member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE):
                        values = pax_records(data)
                    else:
                        if not data.endswith(b'\0') or b'\0' in data[:-1]:
                            raise Stop('ARCHIVE_METADATA_INVALID')
                        key = 'path' if member.type == tarfile.GNUTYPE_LONGNAME else 'linkpath'
                        values = {key: data[:-1].decode('utf-8')}
                    if member.type == tarfile.XGLTYPE:
                        if set(values) & {'path', 'linkpath', 'size'}:
                            raise Stop('ARCHIVE_METADATA_UNSUPPORTED')
                        global_pax.update(values)
                    else:
                        if set(values) & set(pending):
                            raise Stop('ARCHIVE_METADATA_AMBIGUOUS')
                        pending.update(values)
                    continue
                fields = dict(global_pax, **pending)
                name = fields.get('path', member.name)
                target = fields.get('linkpath', member.linkname)
                size = member.size
                if 'size' in fields:
                    if not re.fullmatch(r'[0-9]{1,12}', fields['size']):
                        raise Stop('ARCHIVE_SIZE_INVALID')
                    size = int(fields['size'])
                pending, chain = {}, 0
                kinds = {tarfile.REGTYPE: 'file', tarfile.AREGTYPE: 'file',
                         tarfile.DIRTYPE: 'directory', tarfile.SYMTYPE: 'symlink',
                         tarfile.LNKTYPE: 'hardlink'}
                kind = kinds.get(member.type)
                if kind is None or member.mode & 0o6000:
                    raise Stop('ARCHIVE_TYPE_OR_MODE')
                if not 0 <= size <= MAX_FILE_BYTES or (kind != 'file' and size != 0):
                    raise Stop('ARCHIVE_SIZE_INVALID')
                name = archive_path(name, root, directory=(kind == 'directory'))
                if name == root and kind != 'directory':
                    raise Stop('ARCHIVE_ROOT_INVALID')
                if name in nodes:
                    raise Stop('ARCHIVE_DUPLICATE')
                nodes[name] = (kind, target, size)
                counts[kind] += 1
                file_bytes += size
                reader.skip_payload(size)
                if any(reader.exact((-size) % 512)):
                    raise Stop('ARCHIVE_PADDING_INVALID')
            check_archive_graph(nodes, root)
            return {'status': 'PASSED', 'policy': 'bounded_metadata_audit_r18', 'root': root,
                    'headers': headers, 'members': len(nodes), 'types': counts,
                    'regular_file_bytes': file_bytes, 'tar_stream_bytes': reader.count,
                    'required_regular_files': list(REQUIRED_FILES),
                    'gzip_eof_verified': True, 'members_extracted': False}
    except Stop:
        raise
    except (OSError, EOFError, zlib.error, tarfile.TarError, UnicodeError, ValueError):
        raise Stop('ARCHIVE_FORMAT_INVALID') from None


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
            'Accept-Encoding': 'identity', 'User-Agent': 'ruby-p1-source-measurement-r18'})
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
            archive = Path(directory) / 'source.tar.gz'
            row.update(receive(response, archive, expected, start + 120))
            row['archive'] = audit_archive(archive, version, min(start + 150, time.monotonic() + 60))
        row['elapsed_seconds'] = round(time.monotonic() - start, 3)
        row['temporary_file_removed'] = True
    finally:
        connection.close()


def main():
    report = {'schema': 'ruby-p1-source-container-r18', 'status': 'INCOMPLETE',
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
