"""Compare a fixed exec/noexec fixture; do not install or build anything."""
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import tempfile
import time

SCHEMA = 'ruby-p1-noexec-container-r41'
SUCCESS = 'NOEXEC_FIXTURE_VERIFIED'
CHECKPOINTS = ('identity', 'mount', 'snapshot_before', 'preflight', 'snapshot_after',
               'source_lstat', 'source_read', 'source_elf', 'fixture_create',
               'fixture_write', 'fixture_verify', 'fixture_execute', 'fixture_cleanup',
               'workspace_empty', 'mount_table', 'finished')
REASONS = ('STATE_ENTRY_LIMIT', 'STATE_BYTE_LIMIT', 'STATE_FILE_TYPE',
           'EXEC_FIXTURE_SOURCE', 'EXEC_FIXTURE_ELF', 'EXEC_FIXTURE_CHANGED',
           'EXEC_ERROR_UNEXPECTED', 'EXEC_RESULT_UNEXPECTED', 'EXEC_FIXTURE_CLEANUP',
           'PREFLIGHT_OTHER_REASON', 'PREFLIGHT_DID_NOT_REJECT', 'IDENTITY',
           'SECURITY_BOUNDARY', 'ROOT_NOT_READ_ONLY', 'FIXTURE_INITIAL_STATE',
           'REPO_STATE_COVERAGE', 'RPM_STATE_COVERAGE', 'ENVIRONMENT_OVERRIDE',
           'TIME_LIMIT', 'FIXTURE_MOUNT_MISMATCH', 'PREFLIGHT_STATE_CHANGED',
           'WORKSPACE_NOT_EMPTY', 'MOUNTS_CHANGED', 'IO_ERROR', 'EXEC_TIMEOUT',
           'UNEXPECTED_RUNTIME_ERROR')
PREFLIGHT_REASONS = ('IDENTITY', 'ENVIRONMENT_OVERRIDE', 'PREFIX_EXISTS',
                    'WORKSPACE_PARENT', 'WORKSPACE_NOEXEC', 'SPACE_LOW',
                    'RUST_PRESENT', 'MOUNT_FORMAT', 'MOUNT_UNRESOLVED', 'OTHER_STOP')
STATE_PATHS = ('/etc/yum.repos.d', '/var/lib/rpm', '/usr/lib/sysimage/rpm',
               '/opt/ruby', '/tmp', '/usr/local/bin')
MAX_STATE_BYTES = 128 * 1024 ** 2
MAX_STATE_ENTRIES = 1024


class Stop(Exception):
    pass


def need(condition, reason):
    if not condition:
        raise Stop(reason)


def snapshot(paths=STATE_PATHS):
    """Hash bounded metadata/content, excluding access times and raw path output."""
    digest = hashlib.sha256()
    count = total = 0

    def visit(path):
        nonlocal count, total
        count += 1
        need(count <= MAX_STATE_ENTRIES, 'STATE_ENTRY_LIMIT')
        try:
            meta = path.lstat()
        except FileNotFoundError:
            row = [str(path), 'absent']
        else:
            row = [str(path), meta.st_mode, meta.st_uid, meta.st_gid,
                   meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns]
            if stat.S_ISLNK(meta.st_mode):
                row.append(os.readlink(path))
            elif stat.S_ISREG(meta.st_mode):
                need(meta.st_size <= MAX_STATE_BYTES - total, 'STATE_BYTE_LIMIT')
                with path.open('rb') as handle:
                    data = handle.read(MAX_STATE_BYTES - total + 1)
                total += len(data)
                need(total <= MAX_STATE_BYTES, 'STATE_BYTE_LIMIT')
                row.append(hashlib.sha256(data).hexdigest())
            elif not stat.S_ISDIR(meta.st_mode):
                raise Stop('STATE_FILE_TYPE')
        digest.update(json.dumps(row, ensure_ascii=True, separators=(',', ':')).encode() + b'\n')
        if path.is_dir() and not path.is_symlink():
            for child in sorted(path.iterdir()):
                visit(child)

    for value in paths:
        visit(Path(value))
    return {'sha256': digest.hexdigest(), 'entries': count, 'file_bytes': total}


def elf_bytes(path=Path('/usr/bin/true'), diagnostic=None):
    diagnostic = {} if diagnostic is None else diagnostic
    diagnostic['checkpoint'] = 'source_lstat'
    try:
        meta = path.lstat()
    except FileNotFoundError:
        diagnostic['source_kind'] = 'missing'
    else:
        diagnostic['source_kind'] = ('symlink' if stat.S_ISLNK(meta.st_mode)
                                     else 'regular' if stat.S_ISREG(meta.st_mode)
                                     else 'directory' if stat.S_ISDIR(meta.st_mode) else 'other')
        diagnostic['source_size_bytes'] = meta.st_size
    diagnostic['source_is_file'] = path.is_file()
    need(diagnostic['source_is_file'] and not path.is_symlink(), 'EXEC_FIXTURE_SOURCE')
    diagnostic['checkpoint'] = 'source_read'
    with path.open('rb') as handle:
        data = handle.read(1024 * 1024 + 1)
    diagnostic.update(checkpoint='source_elf', source_bytes_read=len(data),
                      elf64_le=data[:6] == b'\x7fELF\x02\x01', x86_64=data[18:20] == b'\x3e\x00')
    # ELF64, little endian, x86-64. Use the image's binary, not a script/interpreter.
    need(64 <= len(data) <= 1024 * 1024 and data[:6] == b'\x7fELF\x02\x01'
         and data[18:20] == b'\x3e\x00', 'EXEC_FIXTURE_ELF')
    return data


def execute_fixture(parent, data, expect_noexec, diagnostic=None):
    diagnostic = {} if diagnostic is None else diagnostic
    diagnostic['checkpoint'] = 'fixture_create'
    with tempfile.TemporaryDirectory(prefix='ruby-p1-noexec-r41-', dir=parent) as directory:
        target = Path(directory) / 'true'
        diagnostic['checkpoint'] = 'fixture_write'
        with target.open('xb') as handle:
            handle.write(data)
        target.chmod(0o500)
        diagnostic['checkpoint'] = 'fixture_verify'
        need(target.read_bytes() == data, 'EXEC_FIXTURE_CHANGED')
        diagnostic['checkpoint'] = 'fixture_execute'
        try:
            value = subprocess.run([str(target)], env={'PATH': '/usr/bin:/bin', 'LANG': 'C'},
                                   cwd='/', capture_output=True, timeout=5, check=False)
        except OSError as error:
            if type(error.errno) is int and 0 < error.errno <= 4095:
                diagnostic['errno'] = error.errno
            need(expect_noexec and error.errno == errno.EACCES, 'EXEC_ERROR_UNEXPECTED')
            result = {'outcome': 'EACCES', 'errno': errno.EACCES,
                      'returncode': None, 'stdout_bytes': 0, 'stderr_bytes': 0}
        else:
            diagnostic.update(returncode=value.returncode, stdout_bytes=len(value.stdout),
                              stderr_bytes=len(value.stderr))
            need(not expect_noexec and value.returncode == 0 and not value.stdout
                 and not value.stderr, 'EXEC_RESULT_UNEXPECTED')
            result = {'outcome': 'EXECUTED', 'errno': None, 'returncode': 0,
                      'stdout_bytes': 0, 'stderr_bytes': 0}
        diagnostic['checkpoint'] = 'fixture_cleanup'
    need(not os.path.lexists(directory), 'EXEC_FIXTURE_CLEANUP')
    result.update(binary_sha256=hashlib.sha256(data).hexdigest(),
                  binary_bytes=len(data), fixture_removed=True)
    return result


def check_preflight(build, expect_noexec, diagnostic=None):
    """Call the unchanged r39 check only; the complete build/Role is not run."""
    if not expect_noexec:
        return {'called': False, 'reason': 'NOT_RUN_ON_EXEC_CONTROL'}
    try:
        build.preflight()
    except build.Stop as error:
        if diagnostic is not None:
            diagnostic['preflight_reason'] = str(error) if str(error) in PREFLIGHT_REASONS else 'OTHER_STOP'
        need(str(error) == 'WORKSPACE_NOEXEC', 'PREFLIGHT_OTHER_REASON')
    else:
        raise Stop('PREFLIGHT_DID_NOT_REJECT')
    return {'called': True, 'reason': 'WORKSPACE_NOEXEC'}


def identity():
    mode = os.environ.get('RUBY_P1_NOEXEC_MODE')
    need(os.environ.get('RUBY_P1_NOEXEC_PROBE') == 'r41'
         and os.environ.get('RUBY_P1_BUILD_PROBE') == 'r39'
         and mode in ('exec', 'noexec') and os.getuid() == 0
         and platform.system() == 'Linux' and platform.machine() == 'x86_64'
         and platform.python_version() == '3.9.19' and Path('/.dockerenv').is_file(), 'IDENTITY')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                   if '=' in line and not line.startswith('#'))
    need(release.get('ID', '').strip('"') == 'centos'
         and release.get('VERSION_ID', '').strip('"') == '9', 'IDENTITY')
    values = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines()
                  if ':' in line)
    need(values.get('NoNewPrivs', '').strip() == '1'
         and int(values.get('CapEff', '-1').strip(), 16) == 0, 'SECURITY_BOUNDARY')
    need(bool(os.statvfs('/').f_flag & os.ST_RDONLY), 'ROOT_NOT_READ_ONLY')
    need(not Path('/tmp').is_symlink() and not list(Path('/tmp').iterdir())
         and not os.path.lexists('/opt/ruby'), 'FIXTURE_INITIAL_STATE')
    repos = Path('/etc/yum.repos.d')
    repo_files = list(repos.glob('*.repo'))
    need(repos.is_dir() and not repos.is_symlink() and bool(repo_files)
         and all(path.is_file() and not path.is_symlink() for path in repo_files), 'REPO_STATE_COVERAGE')
    need(any(Path(path).is_dir() and not Path(path).is_symlink()
             and any(child.is_file() and not child.is_symlink() and child.stat().st_size > 0
                     for child in Path(path).iterdir())
             for path in ('/var/lib/rpm', '/usr/lib/sysimage/rpm')), 'RPM_STATE_COVERAGE')
    forbidden = ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH', 'PYTHONHOME',
                 'RUBYOPT', 'RUBYLIB', 'GEM_HOME', 'GEM_PATH', 'CONFIGURE_ARGS', 'MAKEFLAGS')
    need(not any(value and (key in forbidden or key.lower().endswith('_proxy'))
                 for key, value in os.environ.items()), 'ENVIRONMENT_OVERRIDE')
    return mode


def main(build):
    report = {'schema': SCHEMA, 'status': 'INCOMPLETE', 'stage': 'identity',
              'scope': 'fixed_tmp_mount_and_build_preflight_only',
              'role_verified': False, 'full_build_entrypoint_executed': False,
              'p1_04_complete': False, 'phase1_complete': False,
              'diagnostic': {'checkpoint': 'identity'}}
    diagnostic = report['diagnostic']
    start = time.monotonic()
    previous = signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Stop('TIME_LIMIT')))
    signal.alarm(45)
    try:
        mode = identity()
        noexec = mode == 'noexec'
        report['mode'] = mode
        report['platform'] = {'os': 'centos-stream-9', 'arch': platform.machine(),
                              'python': platform.python_version()}
        report['stage'] = 'mount'
        diagnostic['checkpoint'] = 'mount'
        mount_text = Path('/proc/self/mountinfo').read_text()
        mounts = build.mount_for('/tmp', mount_text)
        stat_flags = os.statvfs('/tmp').f_flag
        need(mounts['mount_point'] == '/tmp' and mounts['filesystem'] == 'tmpfs'
             and ('noexec' in mounts['options']) is noexec
             and {'rw', 'nosuid', 'nodev'} <= set(mounts['options'])
             and bool(stat_flags & os.ST_NOEXEC) is noexec
             and not stat_flags & os.ST_RDONLY, 'FIXTURE_MOUNT_MISMATCH')
        report['mount'] = {'path': '/tmp', 'filesystem': 'tmpfs',
                           'mountinfo_noexec': noexec, 'statvfs_noexec': noexec,
                           'read_only': False, 'nosuid': True, 'nodev': True}
        diagnostic['checkpoint'] = 'snapshot_before'
        before = snapshot()
        report['stage'] = 'preflight'
        diagnostic['checkpoint'] = 'preflight'
        report['preflight'] = check_preflight(build, noexec, diagnostic)
        diagnostic['checkpoint'] = 'snapshot_after'
        after = snapshot()
        report['guard_state'] = {'before': before, 'after': after, 'unchanged': before == after}
        need(before == after, 'PREFLIGHT_STATE_CHANGED')
        # The controlled executable is created only after guard-state comparison.
        report['stage'] = 'kernel_execution'
        data = elf_bytes(diagnostic=diagnostic)
        report['execution'] = execute_fixture('/tmp', data, noexec, diagnostic)
        diagnostic['checkpoint'] = 'workspace_empty'
        need(not list(Path('/tmp').iterdir()), 'WORKSPACE_NOT_EMPTY')
        diagnostic['checkpoint'] = 'mount_table'
        need(Path('/proc/self/mountinfo').read_text() == mount_text, 'MOUNTS_CHANGED')
        diagnostic['checkpoint'] = 'finished'
        report.update(fixture_directory_empty=True, mount_table_unchanged=True,
                      status=SUCCESS, stage='finished')
    except Stop as error:
        report['reason'] = str(error) if str(error) in REASONS else 'UNEXPECTED_RUNTIME_ERROR'
        diagnostic['exception_type'] = 'Stop'
    except subprocess.TimeoutExpired:
        report['reason'] = 'EXEC_TIMEOUT'
        diagnostic['exception_type'] = 'TimeoutExpired'
    except OSError as error:
        report['reason'] = 'IO_ERROR'
        diagnostic['exception_type'] = 'OSError'
        if type(error.errno) is int and 0 < error.errno <= 4095:
            diagnostic['errno'] = error.errno
    except Exception:
        report['reason'] = 'UNEXPECTED_RUNTIME_ERROR'
        diagnostic['exception_type'] = 'Unexpected'
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
        report['elapsed_seconds'] = round(time.monotonic() - start, 3)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == SUCCESS else 3


if __name__ == '__main__':
    raise SystemExit(main(_build))
