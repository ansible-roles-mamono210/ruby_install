"""DNF metadata/solver measurement. Never download RPMs or execute transactions."""
import contextlib
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
SCHEMA = 'ruby-p1-dependency-container-r21'
MAX_ROWS = 256
TOKEN = re.compile(r'[A-Za-z0-9_+.~:^@-]{1,160}\Z')


class Stop(Exception):
    pass


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


def configure(base, directory, crb):
    base.conf.read()
    check_transport(base.conf)
    base.conf.plugins = False
    base.conf.cacheonly = False
    for key in ('cachedir', 'logdir', 'persistdir'):
        path = Path(directory) / key
        path.mkdir(exist_ok=True)
        setattr(base.conf, key, str(path))
    base.read_all_repos()
    if any(name not in base.repos for name in REPOS) or base.repos['crb'].enabled:
        raise Stop('REPOSITORY_BASELINE_MISMATCH')
    selected = REPOS if crb else REPOS[:2]
    baseline = sorted(token(repo.id) for repo in base.repos.values() if repo.enabled)
    for repo in base.repos.values():
        repo.disable()
        if repo.id in selected:
            check_transport(repo)
            repo.skip_if_unavailable = False
            repo.timeout = 20
            repo.retries = 1
            repo.enable()
    return baseline, list(selected)


def condition(dnf, directory, crb):
    start = time.monotonic()
    with dnf.Base() as base:
        baseline, enabled = configure(base, directory, crb)
        base.fill_sack(load_system_repo=True, load_available_repos=True)
        result = {'crb': crb, 'baseline_enabled_repos': baseline, 'enabled_repos': enabled,
                  'candidates': [], 'missing': [], 'resolution': 'NOT_ATTEMPTED',
                  'install_set': [], 'remove_set': [], 'planned_replacements': []}
        for name in PACKAGES:
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
                    base.install(name, strict=True)
                if requested:
                    base.resolve(allow_erasing=False)
            except dnf.exceptions.MarkingError:
                result['resolution'] = 'MARKING_FAILED'
            except dnf.exceptions.DepsolveError:
                result['resolution'] = 'DEPSOLVE_FAILED'
            else:
                result['resolution'] = 'RESOLVED'
                if requested and base.transaction is not None:
                    result['install_set'] = rows(base.transaction.install_set)
                    result['remove_set'] = rows(base.transaction.remove_set)
                install_names = {p['name'] for p in result['install_set']}
                remove_names = {p['name'] for p in result['remove_set']}
                result['planned_replacements'] = sorted(install_names & remove_names)
        result['elapsed_seconds'] = round(time.monotonic() - start, 3)
    return result


def measure(dnf, rpm, directory):
    before_rpm, before_config = rpm_state(rpm), configuration_state()
    results = []
    try:
        # Two planned conditions, not a failure-triggered retry. Fresh per-condition cache.
        for crb in (False, True):
            work = Path(directory) / ('crb-on' if crb else 'crb-off')
            work.mkdir()
            results.append(condition(dnf, work, crb))
    finally:
        if rpm_state(rpm) != before_rpm or configuration_state() != before_config:
            raise Stop('SYSTEM_STATE_CHANGED')
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
        with silent_dependencies():
            import dnf
            import rpm
            if not str(dnf.__version__).startswith('4.'):
                raise Stop('DNF_VERSION_UNSUPPORTED')
            result['stage'] = 'metadata_and_solver'
            with tempfile.TemporaryDirectory(prefix='ruby-p1-deps-') as directory:
                measured = measure(dnf, rpm, directory)
        signal.alarm(0)
        result = measured
    except Stop as error:
        result['reason'] = str(error)
    except Exception:
        result['reason'] = 'DEPENDENCY_API_OR_METADATA_ERROR'
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == SUCCESS else 3


if __name__ == '__main__':
    raise SystemExit(main())
