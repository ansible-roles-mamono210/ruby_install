"""One explicitly approved dependency-metadata/solver CI run on a disposable VM."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parent
BRANCH = 'plan/ruby-100-p1-env-r1'
HELPERS = {'runtime_smoke.py': '450a33babab510d9d529e309cbfd0ea1a9d76ef4728f1e6190a6a0f41935ecc5',
           'env_probe.py': '7773d3dfd2a9b4d9f77d1f45ad37c6ce2810752dafaebf57780fdd2089ef80b9'}


class Stop(Exception):
    pass


def load(name):
    p = ROOT / (name + '.py')
    if p.name in HELPERS and hashlib.sha256(p.read_bytes()).hexdigest() != HELPERS[p.name]:
        raise Stop('HELPER_CHANGED')
    spec = importlib.util.spec_from_file_location('dependency_' + name, p)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def arguments(runtime, name, run_id):
    return runtime.DOCKER + ['run', '--rm', '--pull=never', '--platform', 'linux/amd64',
        '--name', name, '--label', 'ruby-p1.run=' + run_id,
        '--network', 'bridge', '--read-only', '--user', '65534:65534',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--no-healthcheck',
        '--pids-limit', '64', '--memory', '2g', '--cpus', '1',
        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=1g,mode=1777',
        '--env', 'RUBY_P1_DEPENDENCY_PROBE=1', '--entrypoint', '/usr/bin/python3',
        '-i', runtime.TARGET_CONFIG, '-I', '-B', '-']


def validate(value, worker):
    keys = {'schema', 'status', 'scope', 'python', 'dnf', 'rpm', 'conditions',
            'rpm_before_after', 'configuration_before_after', 'system_state_unchanged',
            'rpm_downloaded', 'transaction_executed', 'build_verified', 'crb_on_resolved'}
    if (type(value) is not dict or set(value) != keys or value['schema'] != worker.SCHEMA
            or value['status'] != worker.SUCCESS or value['python'] != '3.9.19'
            or value['scope'] != 'metadata_and_solver_only'
            or value['system_state_unchanged'] is not True
            or any(value[k] is not False for k in ('rpm_downloaded', 'transaction_executed', 'build_verified'))
            or type(value['crb_on_resolved']) is not bool):
        raise Stop('WORKER_SCHEMA')
    for key in ('dnf', 'rpm'):
        if type(value[key]) is not str or not worker.TOKEN.fullmatch(value[key]):
            raise Stop('WORKER_SCHEMA')
    if not value['dnf'].startswith('4.'):
        raise Stop('WORKER_SCHEMA')
    for key, limit in (('rpm_before_after', 4096), ('configuration_before_after', 128)):
        item = value[key]
        if (type(item) is not dict or set(item) != {'count', 'sha256'}
                or type(item['count']) is not int or not 0 < item['count'] <= limit
                or type(item['sha256']) is not str or len(item['sha256']) != 64
                or any(c not in '0123456789abcdef' for c in item['sha256'])):
            raise Stop('WORKER_SCHEMA')
    if type(value['conditions']) is not list or len(value['conditions']) != 2:
        raise Stop('WORKER_SCHEMA')
    for crb, item in zip((False, True), value['conditions']):
        validate_condition(item, crb, worker)
    if value['crb_on_resolved'] != (value['conditions'][1]['resolution'] == 'RESOLVED'):
        raise Stop('WORKER_SCHEMA')


def validate_packages(values, worker, allowed_repos, maximum=256):
    if type(values) is not list or len(values) > maximum:
        raise Stop('WORKER_SCHEMA')
    for value in values:
        if (type(value) is not dict
                or set(value) != {'name', 'epoch', 'version', 'release', 'arch', 'reponame'}
                or any(type(v) is not str or not worker.TOKEN.fullmatch(v) for v in value.values())
                or value['arch'] not in ('x86_64', 'noarch')
                or value['reponame'] not in allowed_repos):
            raise Stop('WORKER_SCHEMA')


def validate_condition(item, crb, worker):
    keys = {'crb', 'baseline_enabled_repos', 'enabled_repos', 'candidates', 'missing',
            'resolution', 'install_set', 'remove_set', 'planned_replacements', 'elapsed_seconds'}
    enabled = list(worker.REPOS if crb else worker.REPOS[:2])
    if (type(item) is not dict or set(item) != keys or item['crb'] is not crb
            or item['enabled_repos'] != enabled
            or type(item['baseline_enabled_repos']) is not list
            or len(item['baseline_enabled_repos']) > 128
            or any(type(n) is not str or not worker.TOKEN.fullmatch(n) for n in item['baseline_enabled_repos'])
            or 'crb' in item['baseline_enabled_repos']
            or item['resolution'] not in ('RESOLVED', 'MISSING_CANDIDATES', 'MARKING_FAILED', 'DEPSOLVE_FAILED')
            or type(item['elapsed_seconds']) not in (int, float)
            or not math.isfinite(item['elapsed_seconds']) or not 0 <= item['elapsed_seconds'] <= 540
            or type(item['candidates']) is not list or len(item['candidates']) != len(worker.PACKAGES)):
        raise Stop('WORKER_SCHEMA')
    missing = []
    for row, name in zip(item['candidates'], worker.PACKAGES):
        if type(row) is not dict or set(row) != {'name', 'installed', 'available'} or row['name'] != name:
            raise Stop('WORKER_SCHEMA')
        validate_packages(row['installed'], worker, ('@System',), 8)
        validate_packages(row['available'], worker, enabled, 64)
        if any(p['name'] != name for p in row['installed'] + row['available']):
            raise Stop('WORKER_SCHEMA')
        if not row['installed'] and not row['available']:
            missing.append(name)
    if item['missing'] != missing or bool(missing) != (item['resolution'] == 'MISSING_CANDIDATES'):
        raise Stop('WORKER_SCHEMA')
    validate_packages(item['install_set'], worker, enabled)
    validate_packages(item['remove_set'], worker, ('@System',))
    replacements = sorted({p['name'] for p in item['install_set']} & {p['name'] for p in item['remove_set']})
    if (item['planned_replacements'] != replacements
            or (item['resolution'] != 'RESOLVED' and (item['install_set'] or item['remove_set']))):
        raise Stop('WORKER_SCHEMA')


def failure_summary(stdout, worker):
    """Extract a bounded enum-only failure report, never authorize a successful run."""
    if len(stdout.encode()) > 8192:
        return {'state': 'TOO_LARGE'}
    try:
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError
                value[key] = item
            return value
        value = json.loads(stdout, object_pairs_hook=unique)
    except (ValueError, RecursionError):
        return {'state': 'INVALID_JSON'}
    if type(value) is not dict:
        return {'state': 'INVALID_SCHEMA'}
    if value.get('status') == worker.SUCCESS:
        return {'state': 'NOT_A_FAILURE_REPORT'}
    if (set(value) != {'schema', 'status', 'stage', 'reason', 'diagnostic'}
            or value['schema'] != worker.SCHEMA or value['status'] != 'INCOMPLETE'
            or type(value['stage']) is not str or value['stage'] not in ('identity', 'metadata_and_solver')
            or type(value['reason']) is not str or value['reason'] not in worker.FAILURE_REASONS):
        return {'state': 'INVALID_SCHEMA'}
    detail = value['diagnostic']
    allowed = {'stage': worker.STAGES, 'condition': ('none', 'crb_off', 'crb_on'),
               'package': ('none', *worker.PACKAGES), 'reason': worker.FAILURE_REASONS,
               'exception_kind': worker.EXCEPTION_KINDS,
               'errno': ('NONE', 'OTHER', *worker.ERRNO_CODES.values()),
               'state_check': worker.STATE_CHECKS}
    if (type(detail) is not dict or set(detail) != set(allowed)
            or any(type(detail[key]) is not str or detail[key] not in values
                   for key, values in allowed.items())):
        return {'state': 'INVALID_SCHEMA'}
    return {'state': 'VALIDATED_FAILURE_ONLY', 'reason': value['reason'],
            'worker_stage': value['stage'], 'diagnostic': {k: detail[k] for k in allowed}}

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    for name in ('allow-pull', 'allow-repo-metadata', 'allow-solver', 'ephemeral-ci'):
        parser.add_argument('--' + name, action='store_true')
    args = parser.parse_args(argv)
    if (not all((args.allow_pull, args.allow_repo_metadata, args.allow_solver, args.ephemeral_ci))
            or os.environ.get('CIRCLECI') != 'true' or os.environ.get('CIRCLE_BRANCH') != BRANCH
            or platform.system() != 'Linux' or platform.machine() != 'x86_64'):
        print('STOP: EXPLICIT_EPHEMERAL_CI_REQUIRED')
        return 3
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        print('STOP: OUTPUT_UNAVAILABLE_OR_EXISTS')
        return 3
    report = {'schema': 'ruby-p1-dependency-run-r22', 'status': 'INCOMPLETE', 'stage': 'preflight',
              'p1_03_complete': False, 'phase1_complete': False, 'cleanup_confirmed': None}
    runtime = None
    possible = False
    run_id = uuid.uuid4().hex
    name = 'ruby-p1-' + run_id + '-dependency-r22'
    handlers = {}
    try:
        def interrupted(_signum, _frame):
            raise Stop('INTERRUPTED')
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.signal(sig, interrupted)
        runtime, inventory, worker = load('runtime_smoke'), load('env_probe'), load('dependency_container_probe')
        socket = os.stat('/var/run/docker.sock')
        if not stat.S_ISSOCK(socket.st_mode) or socket.st_uid != 0:
            raise Stop('LOCAL_ROOT_DOCKER_SOCKET_REQUIRED')
        report['started_at'] = inventory.now()
        report['source_sha256'] = {n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest()
                                  for n in (*HELPERS, 'dependency_probe.py', 'dependency_container_probe.py')}
        end = time.monotonic() + 840
        report['stage'] = 'target_pull'
        runtime.command(runtime.DOCKER + ['pull', '--quiet', '--platform', 'linux/amd64', runtime.TARGET], end, 240)
        info = runtime.inspect_image(runtime.TARGET, runtime.TARGET_CONFIG, end)
        identity = inventory.registry_identity(runtime.TARGET, info, end)
        if (identity['platform_manifest_digest'] != runtime.TARGET_MANIFEST
                or identity['config_digest'] != runtime.TARGET_CONFIG):
            raise Stop('REGISTRY_MISMATCH')
        report['image'] = identity
        report['stage'] = 'metadata_and_solver'
        possible = True
        remaining = min(540, end - time.monotonic())
        if remaining <= 0:
            raise Stop('TIME_LIMIT')
        result = subprocess.run(arguments(runtime, name, run_id),
                                input=(ROOT / 'dependency_container_probe.py').read_text(),
                                text=True, capture_output=True, timeout=remaining, check=False)
        report['command'] = {'returncode': result.returncode,
                             'stdout_bytes': len(result.stdout.encode()),
                             'stderr_bytes': len(result.stderr.encode())}
        if len(result.stdout.encode()) > 262144:
            raise Stop('WORKER_OUTPUT_REJECTED')
        if result.stderr:
            report['failure_diagnostic'] = failure_summary(result.stdout, worker)
            raise Stop('WORKER_OUTPUT_REJECTED')
        value = json.loads(result.stdout)
        if type(value) is not dict:
            raise Stop('WORKER_SCHEMA')
        if value.get('status') != worker.SUCCESS:
            report['failure_diagnostic'] = failure_summary(result.stdout, worker)
            raise Stop('DEPENDENCY_MEASUREMENT_INCOMPLETE')
        validate(value, worker)
        if result.returncode != 0:
            raise Stop('WORKER_EXIT_MISMATCH')
        report['measurement'] = value
        if value['crb_on_resolved'] is not True:
            raise Stop('CRB_ON_NOT_RESOLVED')
        report.update(status=worker.SUCCESS, stage='finished')
    except Stop as error:
        report['reason'] = str(error)
    except subprocess.TimeoutExpired:
        report['reason'] = 'COMMAND_TIMEOUT'
    except Exception:
        report['reason'] = 'UNEXPECTED_OR_HELPER_ERROR'
    finally:
        if possible:
            report['cleanup_confirmed'] = runtime.cleanup(name, run_id)
            if report['cleanup_confirmed'] is not True:
                report.update(status='INCOMPLETE', reason='CLEANUP_UNCONFIRMED')
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        with os.fdopen(fd, 'w') as output:
            json.dump(report, output, sort_keys=True, indent=2)
            output.write('\n')
    print(report['status'])
    return 0 if report['status'] == 'DEPENDENCY_SOLVER_MEASURED' else 3


if __name__ == '__main__':
    raise SystemExit(main())
