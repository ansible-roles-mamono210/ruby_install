"""One fixed Ruby 3.4.12 evaluation build, only inside a disposable CI container."""
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import ssl
import stat
import subprocess
import tarfile
import tempfile
import time

SCHEMA = 'ruby-p1-build-container-r39'
SUCCESS = 'RUBY_3412_DOCS_ON_RUST_PRESENT_BUILD_VERIFIED'
VERSION = '3.4.12'
PREFIX = '/opt/ruby'
SOURCE_SHA = '5e5d85ad93b0adcccbad47733680f4892bd0078e3342437f7babce01c1872479'
SOURCE_PATH = '/pub/ruby/3.4/ruby-3.4.12.tar.gz'
COMMANDS = ('ruby', 'gem', 'bundle', 'bundler', 'irb', 'erb', 'rdoc', 'ri', 'rake')
CONFIGURE = ('--enable-option-checking=fatal', '--prefix=/opt/ruby',
             '--enable-shared', '--enable-rpath', '--disable-yjit', '--disable-rjit',
             '--enable-install-doc', '--enable-install-rdoc', '--disable-install-capi')
UNKNOWN = '--enable-ruby-p1-intentionally-unknown-r39'
MIN_FREE = 8 * 1024 ** 3
MAX_LOG = 64 * 1024 ** 2
TAIL_BYTES = 16384
STAGES = ('identity', 'dependencies', 'download', 'extract', 'configure_negative',
          'configure', 'build_settings', 'make', 'install', 'runtime', 'commands',
          'documentation', 'final_state', 'finished')


class Stop(Exception):
    pass


def need(condition, reason):
    if not condition:
        raise Stop(reason)


def mount_for(path, text):
    """Select the actual covering mount, including inherited root/noexec flags."""
    candidates = []
    for line in text.splitlines():
        fields = line.split()
        need(len(fields) >= 10 and '-' in fields, 'MOUNT_FORMAT')
        point = re.sub(r'\\(040|011|012|134)', lambda m: chr(int(m[1], 8)), fields[4])
        need('\\' not in point and point.startswith('/'), 'MOUNT_FORMAT')
        if path == point or path.startswith(point.rstrip('/') + '/'):
            candidates.append((len(point), {'mount_point': point,
                'options': sorted(fields[5].split(',')), 'filesystem': fields[fields.index('-') + 1]}))
    need(bool(candidates), 'MOUNT_UNRESOLVED')
    return max(candidates, key=lambda x: x[0])[1]


def preflight():
    need(os.environ.get('RUBY_P1_BUILD_PROBE') == 'r39' and os.getuid() == 0
         and platform.system() == 'Linux' and platform.machine() == 'x86_64'
         and platform.python_version() == '3.9.19' and Path('/.dockerenv').is_file(), 'IDENTITY')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                   if '=' in line and not line.startswith('#'))
    need(release.get('ID', '').strip('"') == 'centos' and
         release.get('VERSION_ID', '').strip('"') == '9', 'IDENTITY')
    forbidden = ('SSLKEYLOGFILE', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'RUBYOPT', 'RUBYLIB',
                 'GEM_HOME', 'GEM_PATH', 'CONFIGURE_ARGS', 'MAKEFLAGS', 'LD_LIBRARY_PATH',
                 'LD_PRELOAD', 'BASH_ENV', 'ENV')
    need(not any(v and (k in forbidden or k.lower().endswith('_proxy'))
                 for k, v in os.environ.items()), 'ENVIRONMENT_OVERRIDE')
    need(not os.path.lexists(PREFIX), 'PREFIX_EXISTS')
    parent = Path('/tmp')
    need(parent.is_dir() and not parent.is_symlink() and os.access(parent, os.W_OK | os.X_OK),
         'WORKSPACE_PARENT')
    mount = mount_for(str(parent.resolve()), Path('/proc/self/mountinfo').read_text())
    need('noexec' not in mount['options'], 'WORKSPACE_NOEXEC')
    free = shutil.disk_usage(parent).free
    need(free >= MIN_FREE and shutil.disk_usage('/opt').free >= MIN_FREE, 'SPACE_LOW')
    need(shutil.which('rustc', path='/usr/local/bin:/usr/bin:/bin') is None and
         not Path('/root/.cargo/bin/rustc').exists(), 'RUST_PRESENT')
    return {'workspace_mount': mount, 'free_bytes_before': free, 'rust_absent_before': True}


def public_state():
    result = {}
    for parent in ('/usr/bin', '/usr/local/bin'):
        for command in COMMANDS:
            path = Path(parent) / command
            if path.is_symlink():
                result[str(path)] = {'kind': 'symlink', 'target': os.readlink(path)}
            elif path.exists():
                need(path.is_file() and path.stat().st_size < 64 * 1024 ** 2, 'PUBLIC_STATE')
                result[str(path)] = {'kind': 'file', 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
            else:
                result[str(path)] = {'kind': 'absent'}
    return result


def source_spec(source):
    selected = [item for item in source.SOURCES if item[0] == VERSION]
    need(selected == [(VERSION, SOURCE_PATH, SOURCE_SHA)] and
         source.HOST == 'cache.ruby-lang.org', 'SOURCE_CHANGED')
    return selected[0]


def download(source, directory, row):
    fixed = source_spec(source)
    context = ssl.create_default_context()
    need(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED, 'TLS_POLICY')
    connection = http.client.HTTPSConnection(source.HOST, 443, timeout=30, context=context)
    path = Path(directory) / 'source.tar.gz'
    try:
        connection.request('GET', fixed[1], headers={'Accept-Encoding': 'identity',
                           'User-Agent': 'ruby-p1-build-measurement-r39'})
        response = connection.getresponse()
        row['http_status'] = response.status
        need(response.status == 200, 'SOURCE_HTTP_STATUS_OR_REDIRECT')
        row.update(source.receive(response, path, SOURCE_SHA, time.monotonic() + 120))
        row['redirect_policy'] = 'no_redirect_followed'
        row['archive'] = source.audit_archive(path, VERSION, time.monotonic() + 60,
                                               allow_boundary_eof=True)
    finally:
        connection.close()
    return path


def extract(source, archive, destination, audit, expected_sha=SOURCE_SHA):
    """Audit first, then explicitly create regular files, directories and finally links.

    No extractall, archive ownership, special modes, or writes through archive links.
    Preserve timestamps for generated release files, avoiding bootstrap regeneration.
    """
    need(hashlib.sha256(archive.read_bytes()).hexdigest() == expected_sha, 'EXTRACT_CHECKSUM')
    need(not destination.exists(), 'EXTRACT_DESTINATION')
    root, nodes, members = 'ruby-' + VERSION, {}, []
    with tarfile.open(archive, 'r:gz', encoding='utf-8', errors='strict') as handle:
        for member in handle:
            need(len(members) < source.MAX_HEADERS, 'EXTRACT_LIMIT')
            kind = {tarfile.REGTYPE: 'file', tarfile.AREGTYPE: 'file', tarfile.DIRTYPE: 'directory',
                    tarfile.SYMTYPE: 'symlink', tarfile.LNKTYPE: 'hardlink'}.get(member.type)
            need(kind is not None and not member.mode & 0o6000, 'EXTRACT_TYPE')
            name = source.archive_path(member.name, root, kind == 'directory')
            need(name not in nodes and (name != root or kind == 'directory'), 'EXTRACT_DUPLICATE')
            need(0 <= member.size <= source.MAX_FILE_BYTES and
                 (kind == 'file' or member.size == 0) and math.isfinite(member.mtime)
                 and 0 <= member.mtime <= 4102444800, 'EXTRACT_METADATA')
            nodes[name] = (kind, member.linkname, member.size)
            members.append((member, name, kind))
        source.check_archive_graph(nodes, root)
        counts = {kind: sum(n[0] == kind for n in nodes.values())
                  for kind in ('file', 'directory', 'symlink', 'hardlink')}
        need(len(nodes) == audit['members'] and counts == audit['types'] and
             sum(n[2] for n in nodes.values()) == audit['regular_file_bytes'], 'EXTRACT_AUDIT_MISMATCH')
        destination.mkdir(mode=0o700)
        for member, name, kind in members:
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if kind == 'directory':
                path.mkdir(exist_ok=True)
            elif kind == 'file':
                with handle.extractfile(member) as input_file, path.open('xb') as output:
                    remaining = member.size
                    while remaining:
                        block = input_file.read(min(65536, remaining))
                        need(bool(block), 'EXTRACT_TRUNCATED')
                        output.write(block)
                        remaining -= len(block)
                path.chmod(0o755 if member.mode & 0o111 else 0o644)
                os.utime(path, (member.mtime, member.mtime))
        # No archive link exists during any regular-file write.
        for member, name, kind in members:
            path = destination / name
            if kind == 'hardlink':
                os.link(destination / member.linkname, path)
            elif kind == 'symlink':
                path.symlink_to(member.linkname)
    return destination / root


def size_tree(path):
    apparent, allocated, seen = 0, 0, set()
    if not Path(path).exists():
        return {'apparent_bytes': 0, 'allocated_bytes': 0}
    for base, dirs, files in os.walk(path, followlinks=False):
        for name in files + dirs:
            try:
                info = (Path(base) / name).lstat()
            except FileNotFoundError:
                continue
            identity = (info.st_dev, info.st_ino)
            if identity not in seen:
                seen.add(identity)
                apparent += info.st_size
                allocated += info.st_blocks * 512
            need(len(seen) < 200000, 'MEASUREMENT_FILE_LIMIT')
    return {'apparent_bytes': apparent, 'allocated_bytes': allocated}


def memory_events_snapshot():
    """Read cgroup-lifetime counters, not a build-only delta or a capacity verdict."""
    required = {'low', 'high', 'max', 'oom', 'oom_kill'}
    allowed = required | {'oom_group_kill'}
    for name in ('/sys/fs/cgroup/memory.events.local', '/sys/fs/cgroup/memory.events'):
        try:
            with Path(name).open('r', encoding='ascii') as handle:
                text = handle.read(8193)
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError):
            return None
        if len(text) > 8192:
            return None
        counters = {}
        for line in text.splitlines():
            fields = line.split()
            if not fields or fields[0] not in allowed:
                continue  # Do not persist unrelated or future kernel fields.
            if (len(fields) != 2 or fields[0] in counters or
                    re.fullmatch(r'[0-9]{1,19}', fields[1]) is None or
                    int(fields[1]) > 2 ** 63 - 1):
                return None
            counters[fields[0]] = int(fields[1])
        if not required <= set(counters):
            return None
        return {'source': name, 'counters': counters}
    return None  # Missing/invalid evidence must never become zero events.


MEMORY_STAT_KEYS = {'anon', 'file', 'kernel', 'kernel_stack', 'pagetables',
                    'sock', 'shmem', 'file_mapped', 'file_dirty', 'file_writeback',
                    'slab_reclaimable', 'slab_unreclaimable'}


def memory_text(name):
    # Fixed, bounded, read-only cgroup files. Never return exception strings.
    try:
        with (Path('/sys/fs/cgroup') / name).open('r', encoding='ascii') as handle:
            text = handle.read(8193)
        return text if len(text) <= 8192 else None
    except (OSError, UnicodeError):
        return None


def memory_scalar(name):
    text = memory_text(name)
    if text is not None and re.fullmatch(r'[0-9]{1,19}', text.strip()):
        value = int(text.strip())
        if value <= 2 ** 63 - 1:
            return value
    return None


def memory_stat_snapshot():
    text = memory_text('memory.stat')
    if text is None:
        return None
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] not in MEMORY_STAT_KEYS:
            continue
        if (len(fields) != 2 or fields[0] in result or
                re.fullmatch(r'[0-9]{1,19}', fields[1]) is None or
                int(fields[1]) > 2 ** 63 - 1):
            return None
        result[fields[0]] = int(fields[1])
    return result if {'anon', 'file'} <= set(result) else None


def memory_snapshot(origin):
    return {'at_seconds': round(time.monotonic() - origin, 6),
            'current_bytes': memory_scalar('memory.current'),
            'lifetime_peak_bytes': memory_scalar('memory.peak'),
            'stat_bytes': memory_stat_snapshot(), 'events': memory_events_snapshot()}


def event_delta(before, after):
    if (before is None or after is None or before['source'] != after['source'] or
            set(before['counters']) != set(after['counters']) or
            any(after['counters'][k] < v for k, v in before['counters'].items())):
        return None
    return {k: after['counters'][k] - v for k, v in before['counters'].items()}


class Meter:
    def __init__(self, workspace):
        self.workspace = workspace
        self.origin = time.monotonic()
        self.active_phase = None
        self.data = {'sample_count': 0, 'sample_interval_seconds': 5,
                     'workspace_peak_allocated_bytes_sampled': 0,
                     'prefix_peak_allocated_bytes_sampled': 0,
                     'combined_peak_allocated_bytes_sampled': 0,
                     'minimum_free_bytes_sampled': shutil.disk_usage('/tmp').free,
                     'memory_peak_bytes': None, 'memory_peak_source': 'unavailable',
                     'memory_events': None, 'memory_phases': []}

    def sample_memory(self):
        snapshot = memory_snapshot(self.origin)
        if self.active_phase is not None:
            row = self.active_phase
            row['sample_count'] += 1
            current = snapshot['current_bytes']
            if current is None:
                row['current_unavailable_samples'] += 1
            else:
                peak = row['current_peak_bytes_sampled']
                row['current_peak_bytes_sampled'] = current if peak is None else max(peak, current)
        return snapshot

    def begin_phase(self, name):
        need(self.active_phase is None and len(self.data['memory_phases']) < 18,
             'MEMORY_PHASE_SEQUENCE')
        row = {'name': name, 'sample_count': 0, 'current_unavailable_samples': 0,
               'current_peak_bytes_sampled': None, 'before': None, 'after': None,
               'events_delta': None, 'completed': False}
        self.data['memory_phases'].append(row)
        self.active_phase = row
        row['before'] = self.sample_memory()

    def end_phase(self, completed):
        if self.active_phase is not None:
            row = self.active_phase
            try:
                row['after'] = self.sample_memory()
                row['events_delta'] = event_delta(row['before']['events'], row['after']['events'])
                row['completed'] = completed
            finally:
                self.active_phase = None

    def sample(self):
        self.sample_memory()
        self.data['memory_events'] = memory_events_snapshot()
        workspace, prefix = size_tree(self.workspace), size_tree(PREFIX)
        self.data['sample_count'] += 1
        for key, value in (('workspace', workspace['allocated_bytes']),
                           ('prefix', prefix['allocated_bytes']),
                           ('combined', workspace['allocated_bytes'] + prefix['allocated_bytes'])):
            field = key + '_peak_allocated_bytes_sampled'
            self.data[field] = max(self.data[field], value)
        free = shutil.disk_usage('/tmp').free
        self.data['minimum_free_bytes_sampled'] = min(self.data['minimum_free_bytes_sampled'], free)
        for name in ('/sys/fs/cgroup/memory.peak', '/sys/fs/cgroup/memory/memory.max_usage_in_bytes'):
            path = Path(name)
            if path.is_file():
                value = path.read_text().strip()
                if value.isdigit():
                    self.data['memory_peak_bytes'] = int(value)
                    self.data['memory_peak_source'] = name
                    break
        need(free >= 256 * 1024 ** 2, 'SPACE_LOW_DURING_BUILD')


def clean_env(home):
    return {'PATH': PREFIX + '/bin:/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
            'HOME': str(home), 'TMPDIR': str(home), 'TZ': 'UTC', 'TERM': 'dumb'}


def run(name, argv, cwd, directory, report, meter, timeout, end, require_success=True):
    meter.begin_phase(name)
    completed = False
    try:
        result = run_command(name, argv, cwd, directory, report, meter, timeout, end, require_success)
        completed = True
        return result
    finally:
        meter.end_phase(completed)


def run_command(name, argv, cwd, directory, report, meter, timeout, end, require_success=True):
    path = Path(directory) / (name + '.log')
    start = time.monotonic()
    budget = min(timeout, end - start)
    need(budget > 0, 'BUILD_TIME_LIMIT')
    process = None
    record = {'name': name, 'returncode': None}
    report['runs'].append(record)
    try:
        with path.open('xb') as log:
            process = subprocess.Popen(argv, cwd=cwd, env=clean_env(directory), stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            sampled = 0
            while process.poll() is None:
                now = time.monotonic()
                need(now - start < budget, 'BUILD_TIME_LIMIT')
                need(path.stat().st_size <= MAX_LOG, 'BUILD_LOG_LIMIT')
                if now - sampled >= 5:
                    meter.sample()
                    sampled = now
                time.sleep(0.2)
            record['returncode'] = process.returncode
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
            record['returncode'] = process.returncode
        record['elapsed_seconds'] = round(time.monotonic() - start, 3)
        if path.exists():
            digest = hashlib.sha256()
            with path.open('rb') as log:
                for block in iter(lambda: log.read(65536), b''):
                    digest.update(block)
                log.seek(max(0, log.tell() - TAIL_BYTES))
                tail = log.read(TAIL_BYTES).decode('utf-8', errors='replace')
            record.update(bytes=path.stat().st_size, sha256=digest.hexdigest(), tail=tail)
    meter.sample()
    need(not require_success or record['returncode'] == 0, 'COMMAND_FAILED')
    return path


def build_settings(directory, configure_log):
    text = (directory / 'Makefile').read_text()
    values = {}
    for key in ('prefix', 'ENABLE_SHARED', 'YJIT_SUPPORT', 'RJIT_SUPPORT', 'DOCTARGETS',
                'INSTALLDOC', 'EXTOUT'):
        match = re.search(r'^' + key + r'\s*=\s*([^\n]*)$', text, re.M)
        need(match is not None, 'BUILD_SETTING_MISSING')
        values[key] = match[1].strip()
    need(values == {'prefix': PREFIX, 'ENABLE_SHARED': 'yes', 'YJIT_SUPPORT': 'no',
                    'RJIT_SUPPORT': 'no', 'DOCTARGETS': 'rdoc nodoc',
                    'INSTALLDOC': 'all', 'EXTOUT': '.ext'}, 'BUILD_SETTING_MISMATCH')
    headers = list(directory.glob('.ext/include/*/ruby/config.h'))
    need(len(headers) == 1, 'BUILD_CONFIG_HEADER')
    header = headers[0].read_text()
    for name in ('USE_YJIT', 'USE_RJIT'):
        need(re.search(r'^#define ' + name + r'\s+0\s*$', header, re.M) is not None, 'JIT_BUILD_ENABLED')
    summary = configure_log.read_text(errors='replace')
    need(re.search(r'\* install doc:\s+rdoc\s*$', summary, re.M) is not None,
         'DOCUMENTATION_SUMMARY_MISMATCH')
    for name in ('YJIT', 'RJIT'):
        need(re.search(r'\* ' + name + r' support:\s+no\s*$', summary, re.M) is not None,
             'JIT_SUMMARY_MISSING')
    return {'makefile_values': values, 'USE_YJIT': 0, 'USE_RJIT': 0,
            'config_header_sha256': hashlib.sha256(headers[0].read_bytes()).hexdigest(),
            'configure_summary_jit_disabled': True}


RUNTIME_RUBY = r'''require 'json'; require 'rbconfig'
require 'openssl'; require 'psych'; require 'zlib'; require 'fiddle'
require 'rdoc/ri/paths'
jit = %w[YJIT RJIT].to_h do |name|
  state = RubyVM.const_defined?(name) ? RubyVM.const_get(name).enabled? : 'absent'
  [name, state]
end
libraries = File.readlines('/proc/self/maps').filter_map do |line|
  path = line.split.last
  File.realpath(path) if path && path.start_with?('/') && File.basename(path).start_with?('libruby')
end.uniq
puts JSON.generate(version: RUBY_VERSION, ruby: File.realpath(RbConfig.ruby),
  prefix: RbConfig::CONFIG['prefix'], shared: RbConfig::CONFIG['ENABLE_SHARED'],
  yjit_build: RbConfig::CONFIG['YJIT_SUPPORT'], rjit_build: RbConfig::CONFIG['RJIT_SUPPORT'],
  jit: jit, shared_libraries: libraries, ri_system: RDoc::RI::Paths.system_dir,
  extensions: {openssl: OpenSSL::OPENSSL_VERSION, psych: Psych::VERSION,
    zlib: Zlib::ZLIB_VERSION, fiddle: Fiddle::VERSION})
'''


def validate_runtime(value):
    need(type(value) is dict and set(value) == {'version', 'ruby', 'prefix', 'shared',
         'yjit_build', 'rjit_build', 'jit', 'shared_libraries', 'ri_system', 'extensions'}, 'RUNTIME_SCHEMA')
    need(value['version'] == VERSION and value['ruby'] == PREFIX + '/bin/ruby'
         and value['prefix'] == PREFIX and value['shared'] == 'yes'
         and value['yjit_build'] == 'no' and value['rjit_build'] == 'no', 'RUNTIME_IDENTITY')
    need(type(value['jit']) is dict and set(value['jit']) == {'YJIT', 'RJIT'} and
         all(v is False or v == 'absent' for v in value['jit'].values()), 'RUNTIME_JIT')
    need(type(value['shared_libraries']) is list and len(value['shared_libraries']) >= 1 and
         all(type(p) is str and p.startswith(PREFIX + '/lib/') and '..' not in p.split('/')
             for p in value['shared_libraries']), 'RUNTIME_SHARED_LIBRARY')
    need(type(value['ri_system']) is str and value['ri_system'].startswith(PREFIX + '/share/ri/')
         and '..' not in value['ri_system'].split('/'), 'DOCUMENTATION_PATH')
    need(type(value['extensions']) is dict and set(value['extensions']) == {'openssl', 'psych', 'zlib', 'fiddle'}
         and all(type(v) is str and 0 < len(v) < 256 for v in value['extensions'].values()), 'EXTENSIONS')


def documentation_arguments(docs):
    # CI420 established rdoc as a supported formatter; isolate the installed system store.
    return [PREFIX + '/bin/ri', '--no-pager', '--format=rdoc',
            '--no-standard-docs', '--doc-dir=' + str(docs), 'String']


def documentation_on(runtime, directory, report, meter, end):
    docs = Path(runtime['ri_system'])
    need(str(docs) == PREFIX + '/share/ri/3.4.0/system' and
         docs.is_dir() and Path(PREFIX) in docs.resolve().parents and
         (docs / 'String' / 'cdesc-String.ri').is_file(), 'STANDARD_DOCUMENTATION_MISSING')
    log = run('ri-String', documentation_arguments(docs), '/tmp',
              directory, report, meter, 30, end)
    need(log.stat().st_size > 100 and 'String' in log.read_text(errors='replace'),
         'STANDARD_DOCUMENTATION_FAILED')
    return {'enabled': True, 'system_dir': str(docs),
            'standard_String_verified': True, 'other_stores_disabled': True}


def validate_shebang(shebang):
    need(re.match(r'^#!\s*' + re.escape(PREFIX + '/bin/ruby') + r'(?:\s|$)',
                  shebang) is not None, 'COMMAND_EXTERNAL_RUBY')


def evaluate(source, installer, dependency, expected, report, directory, meter, end, rust_worker):
    report['public_before'] = public_state()
    report['stage'] = 'dependencies'
    dep = {'schema': rust_worker.SCHEMA, 'status': 'INCOMPLETE', 'stage': 'identity',
           'plan_reference': 'CI430', 'rust_installed': False, 'rust_compiler_checked': False,
           'p1_04_complete': False,
           'rpm_downloaded': False, 'all_signatures_verified': False,
           'transaction_started': False, 'transaction_returned': False,
           'ruby_build_verified': False, 'p1_03_complete': False, 'phase1_complete': False,
           'imported_key_fingerprints': [], 'root_free_bytes_before': shutil.disk_usage('/').free}
    report['dependencies'] = dep
    begin = time.monotonic()
    meter.begin_phase('dependencies')
    dependency_completed = False
    signal.alarm(max(1, min(900, int(end - begin))))
    try:
        with dependency.silent_dependencies():
            import dnf
            import dnf.transaction
            import dnf.callback
            import rpm
            need(str(dnf.__version__) == '4.14.0' and str(rpm.__version__) == '4.16.1.3', 'DEPENDENCY_IDENTITY')
            rust_worker.execute(installer, dependency, dnf, rpm, expected, directory, dep)
        dependency_completed = True
    finally:
        meter.end_phase(dependency_completed)
        signal.alarm(max(1, int(end - time.monotonic())))
    dep['elapsed_seconds'] = round(time.monotonic() - begin, 3)
    need(dep.get('status') == rust_worker.SUCCESS and dep.get('rust_installed') is True
         and dep.get('rust_compiler_checked') is True
         and shutil.which('rustc', path=clean_env(directory)['PATH']) == '/usr/bin/rustc',
         'RUST_COMPILER_UNCONFIRMED')
    report['rust_present_after_dependencies'] = True
    report['stage'] = 'download'
    report['source'] = {'version': VERSION, 'sha256_expected': SOURCE_SHA}
    meter.begin_phase('download')
    completed = False
    try:
        archive = download(source, directory, report['source'])
        completed = True
    finally:
        meter.end_phase(completed)
    report['stage'] = 'extract'
    meter.begin_phase('extract')
    completed = False
    try:
        extracted = extract(source, archive, Path(directory) / 'extracted', report['source']['archive'])
        completed = True
    finally:
        meter.end_phase(completed)
    report['source']['extraction_verified'] = True
    meter.sample()
    build = Path(directory) / 'build'
    build.mkdir(mode=0o700)
    negative = Path(directory) / 'negative'
    negative.mkdir(mode=0o700)
    configure = str(extracted / 'configure')
    report['stage'] = 'configure_negative'
    log = run('configure-negative', [configure, *CONFIGURE, UNKNOWN], negative,
              directory, report, meter, 60, end, require_success=False)
    negative_text = log.read_text(errors='replace')
    need(report['runs'][-1]['returncode'] != 0 and UNKNOWN in negative_text and
         'unrecognized option' in negative_text, 'UNKNOWN_OPTION_NOT_REJECTED')
    report['unknown_option_rejected'] = True
    report['stage'] = 'configure'
    log = run('configure', [configure, *CONFIGURE], build, directory, report, meter, 300, end)
    report['stage'] = 'build_settings'
    report['build_settings'] = build_settings(build, log)
    report['stage'] = 'make'
    run('make', ['/usr/bin/make', '-j1'], build, directory, report, meter, 1500, end)
    report['stage'] = 'install'
    need(not os.path.lexists(PREFIX), 'PREFIX_CREATED_EARLY')
    run('install', ['/usr/bin/make', '-j1', 'install'], build, directory, report, meter, 600, end)
    report['stage'] = 'runtime'
    log = run('runtime', [PREFIX + '/bin/ruby', '-e', RUNTIME_RUBY], '/tmp',
              directory, report, meter, 30, end)
    value = json.loads(log.read_text())
    validate_runtime(value)
    report['runtime'] = value
    report['stage'] = 'commands'
    report['commands'] = []
    for command in COMMANDS:
        path = Path(PREFIX) / 'bin' / command
        need(path.is_file() and os.access(path, os.X_OK) and Path(PREFIX) in path.resolve().parents,
             'COMMAND_MISSING_OR_EXTERNAL')
        if command != 'ruby':
            with path.open('rb') as handle:
                shebang = handle.readline(512).decode('utf-8')
            validate_shebang(shebang)
        log = run('command-' + command, [str(path), '--version'], '/tmp',
                  directory, report, meter, 30, end)
        need(0 < log.stat().st_size < 16384, 'COMMAND_OUTPUT')
        report['commands'].append({'name': command, 'path': str(path), 'returncode': 0})
    report['stage'] = 'documentation'
    report['documentation'] = documentation_on(value, directory, report, meter, end)
    report['stage'] = 'final_state'
    report['public_after'] = public_state()
    need(report['public_before'] == report['public_after'], 'PUBLIC_COMMANDS_CHANGED')
    need(dependency.rpm_state(rpm) == dep['rpm_after'] and
         dependency.configuration_state() == dep['configuration_after'], 'SYSTEM_STATE_CHANGED_BY_BUILD')
    report['prefix_size'] = size_tree(PREFIX)
    meter.sample()
    report.update(stage='finished', status=SUCCESS, ruby_build_verified=True,
                  public_commands_unchanged=True, rpm_and_repo_state_unchanged_by_build=True)


def main(source, installer, dependency, expected, rust_worker):
    report = {'schema': SCHEMA, 'status': 'INCOMPLETE', 'stage': 'identity', 'runs': [],
              'ruby_build_verified': False, 'p1_04_complete': False, 'phase1_complete': False,
              'role_verified': False, 'idempotence_verified': False,
              'condition': {'ruby': VERSION, 'prefix': PREFIX, 'documentation': True, 'rust': True,
                            'make_jobs': 1}, 'configure_argv': list(CONFIGURE)}
    start, directory, meter = time.monotonic(), None, None
    def expired(_sig, _frame):
        raise Stop('BUILD_TIME_LIMIT')
    previous_alarm = signal.signal(signal.SIGALRM, expired)
    signal.alarm(720)
    try:
        report['preflight'] = preflight()
        os.umask(0o077)
        directory = tempfile.mkdtemp(prefix='ruby-p1-build-r39-', dir='/tmp')
        meter = Meter(directory)
        evaluate(source, installer, dependency, expected, report, directory, meter, start + 720, rust_worker)
    except Exception as error:
        report['reason'] = str(error) if type(error) in (Stop, installer.Stop, source.Stop, rust_worker.Stop) else 'API_OR_RUNTIME_ERROR'
        report['error_type'] = type(error).__name__
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_alarm)
        report['elapsed_seconds'] = round(time.monotonic() - start, 3)
        if meter is not None:
            # Preserve partial measurements on failure without replacing its cause.
            # Missing fields remain missing; never synthesize a successful measurement.
            try:
                meter.sample()
                report['prefix_size'] = size_tree(PREFIX)
            except Exception:
                report['measurement_snapshot_error'] = 'FINAL_RESOURCE_SNAPSHOT_FAILED'
            report['resources'] = meter.data
        # CI-only cleanup: bounded log tails survive in JSON; the host deletes this container.
        # This does not implement the Role's failure-workspace retention contract.
        report['ci_container_cleanup_required'] = True
        report['full_workspace_retained'] = False
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == SUCCESS else 3


if __name__ == '__main__':
    raise SystemExit(main(_source, _installer, _dependency, _expected, _rust_worker))
