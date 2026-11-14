"""DNF metadata/solver measurement. Never download RPMs or execute transactions."""
import contextlib
import errno
import hashlib
import json
import logging
import os
from pathlib import Path
import platform
import re
import signal
import tempfile
import time
from urllib.parse import urlsplit

SUCCESS = 'DEPENDENCY_SOLVER_MEASURED'
PACKAGES = ('gcc', 'make', 'tar', 'gzip', 'ca-certificates', 'openssl-devel',
            'libyaml-devel', 'zlib-devel', 'libffi-devel')
REPOS = ('baseos', 'appstream', 'crb')
SCHEMA = 'ruby-p1-dependency-container-r24'
MAX_ROWS = 256
TOKEN = re.compile(r'[A-Za-z0-9_+.~:^@-]{1,160}\Z')
FAILURE_REASONS = frozenset({
    'INVALID_PACKAGE_OR_REPO_FIELD', 'UNEXPECTED_PACKAGE_ORIGIN', 'PACKAGE_COUNT_LIMIT',
    'RPM_DATABASE_LIMIT', 'CONFIGURATION_LIMIT', 'CONFIGURATION_TYPE_OR_SIZE',
    'REPOSITORY_VERIFICATION_DISABLED', 'REPOSITORY_CREDENTIAL_OR_PROXY_PRESENT',
    'REPOSITORY_URL_SCHEME', 'REPOSITORY_BASELINE_MISMATCH', 'SYSTEM_STATE_CHANGED',
    'CONTAINER_IDENTITY_MISMATCH', 'WORKER_TIME_LIMIT', 'DNF_VERSION_UNSUPPORTED',
    'DEPENDENCY_API_OR_METADATA_ERROR', 'DNF_TEMP_ROOT_UNEXPECTED'})
STAGES = frozenset({'identity', 'silence_setup', 'dnf_import', 'rpm_import', 'dnf_version',
    'workspace_create', 'rpm_before', 'configuration_before', 'condition_workspace',
    'temporary_root', 'base_open', 'configuration_read', 'transport_check', 'cache_directories',
    'repository_read', 'repository_baseline', 'repository_transport', 'metadata_load',
    'candidate_query', 'package_mark', 'solver', 'transaction_summary', 'base_close',
    'rpm_after', 'configuration_after', 'state_compare', 'result_versions',
    'workspace_cleanup', 'silence_restore'})
EXCEPTION_KINDS = frozenset({'STOP', 'PERMISSION_ERROR', 'FILE_NOT_FOUND', 'TIMEOUT',
    'OS_ERROR', 'MODULE_NOT_FOUND', 'IMPORT_ERROR', 'ATTRIBUTE_ERROR', 'TYPE_ERROR',
    'VALUE_ERROR', 'KEY_ERROR', 'RUNTIME_ERROR', 'MEMORY_ERROR', 'OTHER'})
ERRNO_CODES = {getattr(errno, n): n for n in
               ('EACCES', 'EPERM', 'EROFS', 'ENOENT', 'ENOSPC', 'ENOMEM', 'ETIMEDOUT', 'EIO')}
STATE_CHECKS = frozenset({'NOT_STARTED', 'PENDING', 'MATCH', 'CHANGED', 'ERROR'})
CHAIN_LIMIT = 4
FRAME_LIMIT = 64
DNF_ERROR_NAMES = {
    'Error': 'DNF_ERROR', 'RepoError': 'DNF_REPO_ERROR',
    'MetadataError': 'DNF_METADATA_ERROR', 'DatabaseError': 'DNF_DATABASE_ERROR',
    'ConfigError': 'DNF_CONFIG_ERROR', 'LockError': 'DNF_LOCK_ERROR',
    'ProcessLockError': 'DNF_PROCESS_LOCK_ERROR', 'ThreadLockError': 'DNF_THREAD_LOCK_ERROR'}
CHAIN_KINDS = EXCEPTION_KINDS | frozenset(DNF_ERROR_NAMES.values()) | {'LIBDNF_ERROR'}
DNF_FRAMES = {
    ('dnf.base', 'fill_sack'): 'FILL_SACK',
    ('dnf.base', '_add_repo_to_sack'): 'ADD_REPOSITORY',
    ('dnf.base', '_setup_excludes_includes'): 'EXCLUDES',
    ('dnf.base', '_setup_modular_excludes'): 'MODULE_FILTER',
    ('dnf.sack', '_build_sack'): 'SACK_CREATE',
    ('dnf.sack', '__init__'): 'SACK_CREATE',
    ('dnf.sack', '_configure'): 'SACK_CONFIGURE',
    ('dnf.repo', 'load'): 'REPOSITORY_LOAD',
    ('dnf.lock', 'build_metadata_lock'): 'METADATA_LOCK_CREATE',
    ('dnf.lock', '_fit_lock_dir'): 'LOCK_DIRECTORY',
    ('dnf.lock', '__enter__'): 'LOCK_ENTER',
    ('dnf.lock', '_try_lock'): 'LOCK_ACQUIRE',
    ('dnf.lock', '__exit__'): 'LOCK_EXIT'}
FRAME_TAGS = frozenset(DNF_FRAMES.values()) | {'UNMAPPED'}


class Stop(Exception):
    pass


def mark(trace, stage):
    if trace is not None:
        trace['stage'] = stage


def failure_reason(error):
    if (type(error) is Stop and len(error.args) == 1 and type(error.args[0]) is str
            and error.args[0] in FAILURE_REASONS):
        return error.args[0]
    return 'DEPENDENCY_API_OR_METADATA_ERROR'


def exception_codes(error):
    """Classify built-in exceptions without reading their text."""
    kind = 'OTHER'
    for cls, label in ((Stop, 'STOP'), (PermissionError, 'PERMISSION_ERROR'),
            (FileNotFoundError, 'FILE_NOT_FOUND'), (TimeoutError, 'TIMEOUT'),
            (OSError, 'OS_ERROR'), (ModuleNotFoundError, 'MODULE_NOT_FOUND'),
            (ImportError, 'IMPORT_ERROR'), (AttributeError, 'ATTRIBUTE_ERROR'),
            (TypeError, 'TYPE_ERROR'), (ValueError, 'VALUE_ERROR'), (KeyError, 'KEY_ERROR'),
            (RuntimeError, 'RUNTIME_ERROR'), (MemoryError, 'MEMORY_ERROR')):
        if isinstance(error, cls):
            kind = label
            break
    code = 'NONE'
    if isinstance(error, OSError):
        number = error.errno
        code = ERRNO_CODES.get(number, 'OTHER') if type(number) is int else 'OTHER'
    return kind, code


def error_chain(error):
    """Bounded passive observations, never formatted traceback, locals or messages."""
    result, seen, link = [], set(), 'SELF'
    while error is not None:
        if id(error) in seen:
            return {'state': 'CYCLE', 'items': result}
        if len(result) == CHAIN_LIMIT:
            return {'state': 'LIMIT', 'items': result}
        seen.add(id(error))
        kind, code = exception_codes(error)
        cls = type(error)
        if cls.__module__ == 'dnf.exceptions':
            kind = DNF_ERROR_NAMES.get(cls.__name__, kind)
        elif (cls.__module__, cls.__name__) == ('libdnf.error', 'Error'):
            kind = 'LIBDNF_ERROR'
        frame_tag, count, tb = 'UNMAPPED', 0, error.__traceback__
        while tb is not None and count < FRAME_LIMIT:
            # Only module/function identifiers are matched in memory. No paths or locals.
            module = tb.tb_frame.f_globals.get('__name__')
            if type(module) is str:
                label = DNF_FRAMES.get((module, tb.tb_frame.f_code.co_name))
                if label is not None:
                    frame_tag = label
            count += 1
            tb = tb.tb_next
        result.append({'link': link, 'kind': kind, 'errno': code, 'frame': frame_tag,
                       'frames': 'LIMIT' if tb is not None else 'COMPLETE'})
        if error.__cause__ is not None:
            error, link = error.__cause__, 'CAUSE'
        elif not error.__suppress_context__:
            error, link = error.__context__, 'CONTEXT'
        else:
            error = None
    return {'state': 'COMPLETE', 'items': result}


def remember_failure(trace, error):
    """Record fixed enums only; do not retain exception or frame objects."""
    if trace is None or trace['failure'] is not None:
        return
    kind, code = exception_codes(error)
    trace['failure'] = {'stage': trace['stage'], 'condition': trace['condition'],
                        'package': trace['package'], 'reason': failure_reason(error),
                        'exception_kind': kind, 'errno': code,
                        'error_chain': error_chain(error)}


def token(value):
    if type(value) is not str or not TOKEN.fullmatch(value):
        raise Stop('INVALID_PACKAGE_OR_REPO_FIELD')
    return value


def package(pkg):
    row = {key: token(str(getattr(pkg, key)))
           for key in ('name', 'epoch', 'version', 'release', 'arch', 'reponame')}
    if row['arch'] not in ('x86_64', 'noarch') or row['reponame'] not in (*REPOS, '@System'):
        raise Stop('UNEXPECTED_PACKAGE_ORIGIN')
    return row


def rows(packages, maximum=MAX_ROWS):
    result = []
    for pkg in packages:
        if len(result) >= maximum:
            raise Stop('PACKAGE_COUNT_LIMIT')
        result.append(package(pkg))
    return sorted(result, key=lambda p: tuple(p.values()))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def rpm_state(rpm):
    ts = rpm.TransactionSet()
    values = []
    for hdr in ts.dbMatch():
        if len(values) >= 4096:
            raise Stop('RPM_DATABASE_LIMIT')
        values.append(tuple(str(hdr[k]) for k in ('name', 'epoch', 'version', 'release', 'arch')))
    del ts
    return {'count': len(values), 'sha256': digest(sorted(values))}


def configuration_state():
    paths = [Path('/etc/dnf/dnf.conf')]
    for folder, pattern in (('/etc/yum.repos.d', '*.repo'), ('/etc/dnf/modules.d', '*.module')):
        paths += sorted(Path(folder).glob(pattern))
    if len(paths) > 128:
        raise Stop('CONFIGURATION_LIMIT')
    values = []
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise Stop('CONFIGURATION_TYPE_OR_SIZE')
        values.append((str(path), hashlib.sha256(path.read_bytes()).hexdigest()))
    return {'count': len(values), 'sha256': digest(values)}


def check_transport(conf):
    # Preserve the image's transports, but do not accept TLS bypass or credentials.
    if not conf.sslverify or not conf.gpgcheck:
        raise Stop('REPOSITORY_VERIFICATION_DISABLED')
    for key in ('proxy', 'proxy_username', 'proxy_password', 'username', 'password',
                'sslclientcert', 'sslclientkey'):
        if getattr(conf, key, ''):
            raise Stop('REPOSITORY_CREDENTIAL_OR_PROXY_PRESENT')
    for value in list(getattr(conf, 'baseurl', [])) + [getattr(conf, 'metalink', ''),
                                                    getattr(conf, 'mirrorlist', '')]:
        if value:
            parsed = urlsplit(value)
            if parsed.username is not None or parsed.password is not None:
                raise Stop('REPOSITORY_CREDENTIAL_OR_PROXY_PRESENT')
            if parsed.scheme not in ('http', 'https') or not parsed.hostname:
                raise Stop('REPOSITORY_URL_SCHEME')


def configure(base, directory, crb, trace=None):
    mark(trace, 'configuration_read')
    base.conf.read()
    mark(trace, 'transport_check')
    check_transport(base.conf)
    base.conf.plugins = False
    base.conf.cacheonly = False
    mark(trace, 'cache_directories')
    for key in ('cachedir', 'logdir', 'persistdir'):
        path = Path(directory) / key
        path.mkdir(exist_ok=True)
        setattr(base.conf, key, str(path))
    mark(trace, 'repository_read')
    base.read_all_repos()
    mark(trace, 'repository_baseline')
    if any(name not in base.repos for name in REPOS) or base.repos['crb'].enabled:
        raise Stop('REPOSITORY_BASELINE_MISMATCH')
    selected = REPOS if crb else REPOS[:2]
    baseline = sorted(token(repo.id) for repo in base.repos.values() if repo.enabled)
    for repo in base.repos.values():
        repo.disable()
        if repo.id in selected:
            mark(trace, 'repository_transport')
            check_transport(repo)
            repo.skip_if_unavailable = False
            repo.timeout = 20
            repo.retries = 1
            repo.enable()
    return baseline, list(selected)


@contextlib.contextmanager
def temporary_root(dnf, directory, trace=None):
    # DNF 4's non-root Conf constructor calls getCacheDir before conf can be set.
    # Keep that bootstrap cache and later lock helpers in the existing /tmp tmpfs.
    # This is an internal DNF constant, scoped to this single-threaded worker.
    mark(trace, 'temporary_root')
    original = getattr(dnf.const, 'TMPDIR', None)
    if type(original) is not str or original not in ('/var/tmp', '/var/tmp/'):
        raise Stop('DNF_TEMP_ROOT_UNEXPECTED')
    cache_root = Path(directory) / 'dnf-bootstrap'
    cache_root.mkdir(mode=0o700)
    dnf.const.TMPDIR = str(cache_root)
    try:
        mark(trace, 'base_open')
        yield
    finally:
        dnf.const.TMPDIR = original


def condition(dnf, directory, crb, trace=None):
    start = time.monotonic()
    with temporary_root(dnf, directory, trace), dnf.Base() as base:
        baseline, enabled = configure(base, directory, crb, trace)
        mark(trace, 'metadata_load')
        base.fill_sack(load_system_repo=True, load_available_repos=True)
        result = {'crb': crb, 'baseline_enabled_repos': baseline, 'enabled_repos': enabled,
                  'candidates': [], 'missing': [], 'resolution': 'NOT_ATTEMPTED',
                  'install_set': [], 'remove_set': [], 'planned_replacements': []}
        for name in PACKAGES:
            if trace is not None:
                trace['package'] = name
            mark(trace, 'candidate_query')
            installed = rows(base.sack.query().installed().filter(name=name), 8)
            available = rows(base.sack.query().available().filter(
                name=name, arch=['x86_64', 'noarch']), 64)
            result['candidates'].append({'name': name, 'installed': installed, 'available': available})
            if not installed and not available:
                result['missing'].append(name)
        if result['missing']:
            result['resolution'] = 'MISSING_CANDIDATES'
        else:
            requested = [row['name'] for row in result['candidates'] if not row['installed']]
            try:
                # Model state=present: already-installed requested packages are not marked for update.
                for name in requested:
                    if trace is not None:
                        trace['package'] = name
                    mark(trace, 'package_mark')
                    base.install(name, strict=True)
                if trace is not None:
                    trace['package'] = 'none'
                if requested:
                    mark(trace, 'solver')
                    base.resolve(allow_erasing=False)
            except dnf.exceptions.MarkingError:
                result['resolution'] = 'MARKING_FAILED'
            except dnf.exceptions.DepsolveError:
                result['resolution'] = 'DEPSOLVE_FAILED'
            else:
                result['resolution'] = 'RESOLVED'
                mark(trace, 'transaction_summary')
                if requested and base.transaction is not None:
                    result['install_set'] = rows(base.transaction.install_set)
                    result['remove_set'] = rows(base.transaction.remove_set)
                install_names = {p['name'] for p in result['install_set']}
                remove_names = {p['name'] for p in result['remove_set']}
                result['planned_replacements'] = sorted(install_names & remove_names)
        result['elapsed_seconds'] = round(time.monotonic() - start, 3)
        if trace is not None:
            trace['package'] = 'none'
        mark(trace, 'base_close')
    return result


def measure(dnf, rpm, directory, trace=None):
    mark(trace, 'rpm_before')
    before_rpm = rpm_state(rpm)
    mark(trace, 'configuration_before')
    before_config = configuration_state()
    if trace is not None:
        trace['state_check'] = 'PENDING'
    results = []
    try:
        # Two planned conditions, not a failure-triggered retry. Fresh per-condition cache.
        for crb in (False, True):
            if trace is not None:
                trace.update(condition='crb_on' if crb else 'crb_off', package='none')
            mark(trace, 'condition_workspace')
            work = Path(directory) / ('crb-on' if crb else 'crb-off')
            work.mkdir()
            results.append(condition(dnf, work, crb, trace))
    except Exception as error:
        remember_failure(trace, error)
        raise
    finally:
        try:
            if trace is not None:
                trace.update(condition='none', package='none')
            mark(trace, 'rpm_after')
            after_rpm = rpm_state(rpm)
            mark(trace, 'configuration_after')
            after_config = configuration_state()
            mark(trace, 'state_compare')
            if after_rpm != before_rpm or after_config != before_config:
                if trace is not None:
                    trace['state_check'] = 'CHANGED'
                raise Stop('SYSTEM_STATE_CHANGED')
            if trace is not None:
                trace['state_check'] = 'MATCH'
        except Exception as error:
            if trace is not None and trace['state_check'] != 'CHANGED':
                trace['state_check'] = 'ERROR'
            remember_failure(trace, error)
            raise
    mark(trace, 'result_versions')
    return {'schema': SCHEMA, 'status': SUCCESS, 'python': platform.python_version(),
            'dnf': token(str(dnf.__version__)), 'rpm': token(str(rpm.__version__)),
            'scope': 'metadata_and_solver_only', 'conditions': results,
            'rpm_before_after': before_rpm, 'configuration_before_after': before_config,
            'system_state_unchanged': True, 'rpm_downloaded': False,
            'transaction_executed': False, 'build_verified': False,
            'crb_on_resolved': results[1]['resolution'] == 'RESOLVED'}


@contextlib.contextmanager
def silent_dependencies():
    # Native librpm/librepo output is not an artifact channel.
    saved = [os.dup(1), os.dup(2)]
    try:
        with open(os.devnull, 'w') as sink:
            os.dup2(sink.fileno(), 1)
            os.dup2(sink.fileno(), 2)
            logging.disable(logging.CRITICAL)
            yield
    finally:
        for fd, original in zip((1, 2), saved):
            os.dup2(original, fd)
            os.close(original)


def main():
    result = {'schema': SCHEMA, 'status': 'INCOMPLETE', 'stage': 'identity'}
    trace = {'stage': 'identity', 'condition': 'none', 'package': 'none',
             'failure': None, 'state_check': 'NOT_STARTED'}
    alarm_set = False
    try:
        if (os.environ.get('RUBY_P1_DEPENDENCY_PROBE') != '1' or os.getuid() != 65534
                or platform.system() != 'Linux' or platform.machine() != 'x86_64'
                or platform.python_version() != '3.9.19'):
            raise Stop('CONTAINER_IDENTITY_MISMATCH')
        release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                       if '=' in line and not line.startswith('#'))
        if release.get('ID', '').strip('"') != 'centos' or release.get('VERSION_ID', '').strip('"') != '9':
            raise Stop('CONTAINER_IDENTITY_MISMATCH')
        if any(k.lower().endswith('_proxy') and v for k, v in os.environ.items()):
            raise Stop('REPOSITORY_CREDENTIAL_OR_PROXY_PRESENT')
        def expired(_signum, _frame):
            raise Stop('WORKER_TIME_LIMIT')
        signal.signal(signal.SIGALRM, expired)
        signal.alarm(510)
        alarm_set = True
        mark(trace, 'silence_setup')
        with silent_dependencies():
            mark(trace, 'dnf_import')
            import dnf
            mark(trace, 'rpm_import')
            import rpm
            mark(trace, 'dnf_version')
            if not str(dnf.__version__).startswith('4.'):
                raise Stop('DNF_VERSION_UNSUPPORTED')
            result['stage'] = 'metadata_and_solver'
            mark(trace, 'workspace_create')
            with tempfile.TemporaryDirectory(prefix='ruby-p1-deps-', dir='/tmp') as directory:
                measured = measure(dnf, rpm, directory, trace)
                mark(trace, 'workspace_cleanup')
            mark(trace, 'silence_restore')
        result = measured
    except Stop as error:
        remember_failure(trace, error)
        result['reason'] = failure_reason(error)
    except Exception as error:
        remember_failure(trace, error)
        result['reason'] = 'DEPENDENCY_API_OR_METADATA_ERROR'
    finally:
        if alarm_set:
            signal.alarm(0)
    if result['status'] != SUCCESS:
        result['diagnostic'] = dict(trace['failure'], state_check=trace['state_check'])
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == SUCCESS else 3


if __name__ == '__main__':
    raise SystemExit(main())
