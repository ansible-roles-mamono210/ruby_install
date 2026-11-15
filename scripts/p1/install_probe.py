"""Host gate for one explicitly approved r27 disposable-container installation."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parent
HELPERS = {
    'dependency_probe.py': '240c2304eb28c8d769cb6d5cfaf2ae964175e50339d9debf358e7331a8807018',
    'dependency_container_probe.py': '2118deac29ca85c050e4cee8291b3a062f7d9646fe0c69739562794922904b1d',
    'runtime_smoke.py': '450a33babab510d9d529e309cbfd0ea1a9d76ef4728f1e6190a6a0f41935ecc5',
    'env_probe.py': '7773d3dfd2a9b4d9f77d1f45ad37c6ce2810752dafaebf57780fdd2089ef80b9'}
BRANCH = 'plan/ruby-100-p1-env-r1'


class Stop(Exception):
    pass


def load(name):
    import importlib.util
    path = ROOT / (name + '.py')
    if path.name in HELPERS and hashlib.sha256(path.read_bytes()).hexdigest() != HELPERS[path.name]:
        raise Stop('HELPER_CHANGED')
    spec = importlib.util.spec_from_file_location('r27_' + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def arguments(runtime, name, run_id):
    result = runtime.DOCKER + ['run', '--rm', '--pull=never', '--platform', 'linux/amd64',
        '--name', name, '--label', 'ruby-p1.run=' + run_id, '--network', 'bridge',
        '--user', '0:0', '--cap-drop', 'ALL']
    for capability in ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'FSETID', 'SETFCAP',
                       'SETGID', 'SETUID', 'SYS_CHROOT'):
        result += ['--cap-add', capability]
    return result + ['--security-opt', 'no-new-privileges', '--no-healthcheck',
        '--pids-limit', '128', '--memory', '2g', '--cpus', '1',
        '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=1g,mode=1777',
        '--env', 'RUBY_P1_INSTALL_PROBE=r27', '--entrypoint', '/usr/bin/python3',
        '-i', runtime.TARGET_CONFIG, '-I', '-B', '-']


def valid_digest(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def number(value, maximum):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum


def validate(value, expected, worker, dependency_host, dependency):
    keys = {'schema', 'status', 'stage', 'rpm_downloaded', 'all_signatures_verified',
            'transaction_started', 'transaction_returned', 'ruby_build_verified',
            'p1_03_complete', 'phase1_complete', 'imported_key_fingerprints',
            'root_free_bytes_before', 'rpm_before', 'configuration_before',
            'substitutions', 'transaction_plan_matches_ci416', 'plan',
            'public_key_file_sha256', 'rpms', 'delta', 'rpm_after',
            'configuration_after', 'candidates_present', 'smoke', 'elapsed_seconds', 'rpm_tsflags',
            'transaction_error_count'}
    if (type(value) is not dict or set(value) != keys or value['schema'] != worker.SCHEMA
            or value['status'] != worker.SUCCESS or value['stage'] != 'finished'
            or any(value[k] is not True for k in ('rpm_downloaded', 'all_signatures_verified',
                    'transaction_started', 'transaction_returned', 'transaction_plan_matches_ci416'))
            or any(value[k] is not False for k in ('ruby_build_verified', 'p1_03_complete', 'phase1_complete'))
            or value['rpm_before'] != expected['baseline_rpm']
            or value['configuration_before'] != expected['baseline_configuration']
            or value['configuration_after'] != value['configuration_before']
            or value['plan'] != {k: expected[k] for k in ('install_set', 'remove_set')}
            or value['candidates_present'] != list(dependency.PACKAGES)
            or not dependency_host.valid_substitutions(value['substitutions'], dependency, success=True)
            or not number(value['elapsed_seconds'], 960)
            or type(value['root_free_bytes_before']) is not int
            or value['root_free_bytes_before'] < worker.MIN_FREE):
        raise Stop('WORKER_SCHEMA')
    if type(value['transaction_error_count']) is not int or value['transaction_error_count'] != 0:
        raise Stop('WORKER_SCHEMA')
    if (type(value['rpm_tsflags']) is not list or
            any(type(flag) is not str or flag != 'nodocs' for flag in value['rpm_tsflags'])):
        raise Stop('WORKER_SCHEMA')
    for name, limit, regex in (('public_key_file_sha256', 4, r'[0-9a-f]{64}'),
                              ('imported_key_fingerprints', 4, r'[0-9A-F]{40,64}')):
        rows = value[name]
        if (type(rows) is not list or len(rows) > limit or
                (name == 'public_key_file_sha256' and not rows) or
                any(type(s) is not str or not re.fullmatch(regex, s) for s in rows)):
            raise Stop('WORKER_SCHEMA')
    delta = value['delta']
    if (type(delta) is not dict or set(delta) != {'added_or_upgraded', 'replaced_old_versions',
            'new_package_names', 'public_keys_added', 'exact_plan_match'}
            or delta['exact_plan_match'] is not True
            or any(type(delta[k]) is not int for k in delta if k != 'exact_plan_match')
            or delta['added_or_upgraded'] != 30 or delta['replaced_old_versions'] != 9
            or delta['new_package_names'] != 21 or not 0 <= delta['public_keys_added'] <= 4):
        raise Stop('WORKER_SCHEMA')
    after = value['rpm_after']
    if (type(after) is not dict or set(after) != {'count', 'sha256'}
            or type(after['count']) is not int
            or after['count'] != 184 + delta['public_keys_added'] or not valid_digest(after['sha256'])):
        raise Stop('WORKER_SCHEMA')
    records = value['rpms']
    if type(records) is not list or len(records) != 30:
        raise Stop('WORKER_SCHEMA')
    for row in records:
        if (type(row) is not dict or set(row) != {'package', 'sha256', 'bytes', 'signature_verified'}
                or row['signature_verified'] is not True or not valid_digest(row['sha256'])
                or type(row['bytes']) is not int or not 0 < row['bytes'] <= worker.MAX_DOWNLOAD):
            raise Stop('WORKER_SCHEMA')
        dependency_host.validate_packages([row['package']], dependency, dependency.REPOS)
    if (sorted((r['package'] for r in records), key=worker.key)
            != sorted(expected['install_set'], key=worker.key)
            or sum(r['bytes'] for r in records) > worker.MAX_DOWNLOAD):
        raise Stop('WORKER_SCHEMA')
    if type(value['smoke']) is not list or len(value['smoke']) != 3:
        raise Stop('WORKER_SCHEMA')
    for item, name in zip(value['smoke'], worker.SMOKE_NAMES):
        if (type(item) is not dict or set(item) != {'name', 'returncode', 'stderr_bytes',
                'output_match', 'elapsed_seconds'} or item['name'] != name
                or type(item['returncode']) is not int or item['returncode'] != 0
                or type(item['stderr_bytes']) is not int or item['stderr_bytes'] != 0
                or item['output_match'] is not True or not number(item['elapsed_seconds'], 95)):
            raise Stop('WORKER_SCHEMA')


def failure(value, worker):
    # Failed workers never authorize success or emit arbitrary exceptions/URLs.
    result = {'stage': 'UNKNOWN', 'reason': 'UNCLASSIFIED'}
    if type(value) is dict and value.get('schema') == worker.SCHEMA:
        if type(value.get('stage')) is str and value['stage'] in worker.STAGES:
            result['stage'] = value['stage']
        if type(value.get('reason')) is str and value['reason'] in worker.REASONS:
            result['reason'] = value['reason']
        for k in ('rpm_downloaded', 'all_signatures_verified', 'transaction_started', 'transaction_returned'):
            if type(value.get(k)) is bool:
                result[k] = value[k]
        if type(value.get('transaction_error_count')) is int and value['transaction_error_count'] >= 0:
            result['transaction_error_count'] = value['transaction_error_count']
        records = value.get('smoke')
        if type(records) is list and len(records) <= 3:
            clean = []
            for row in records:
                if (type(row) is dict and type(row.get('name')) is str and row['name'] in worker.SMOKE_NAMES
                        and type(row.get('returncode')) is int and -255 <= row['returncode'] <= 255
                        and type(row.get('stderr_bytes')) is int and 0 <= row['stderr_bytes'] <= 1048576
                        and type(row.get('output_match')) is bool):
                    clean.append({k: row[k] for k in ('name', 'returncode', 'stderr_bytes', 'output_match')})
            result['smoke'] = clean
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    for flag in ('allow-pull', 'allow-install', 'allow-ci416-replacements', 'ephemeral-ci'):
        parser.add_argument('--' + flag, action='store_true')
    args = parser.parse_args(argv)
    if (not all((args.allow_pull, args.allow_install, args.allow_ci416_replacements, args.ephemeral_ci))
            or os.environ.get('CIRCLECI') != 'true' or os.environ.get('CIRCLE_BRANCH') != BRANCH
            or platform.system() != 'Linux' or platform.machine() != 'x86_64'):
        print('STOP: EXPLICIT_EPHEMERAL_INSTALL_APPROVAL_REQUIRED')
        return 3
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        print('STOP: OUTPUT_UNAVAILABLE_OR_EXISTS')
        return 3
    report = {'schema': 'ruby-p1-install-run-r27', 'status': 'INCOMPLETE', 'stage': 'preflight',
              'p1_03_complete': False, 'phase1_complete': False, 'cleanup_confirmed': None}
    possible = False
    runtime = None
    run_id = uuid.uuid4().hex
    name = 'ruby-p1-' + run_id + '-install-r27'
    handlers = {}
    try:
        def interrupted(_sig, _frame):
            raise Stop('INTERRUPTED')
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.signal(sig, interrupted)
        runtime, inventory = load('runtime_smoke'), load('env_probe')
        worker, dependency_host = load('install_container_probe'), load('dependency_probe')
        dependency = load('dependency_container_probe')
        plan_text = (ROOT / 'ci416_dependency_plan.json').read_text()
        if hashlib.sha256(plan_text.encode()).hexdigest() != worker.PLAN_SHA:
            raise Stop('BASELINE_PLAN_CHANGED')
        expected = json.loads(plan_text)
        socket = os.stat('/var/run/docker.sock')
        if not stat.S_ISSOCK(socket.st_mode) or socket.st_uid != 0:
            raise Stop('LOCAL_ROOT_DOCKER_SOCKET_REQUIRED')
        report['started_at'] = inventory.now()
        report['source_sha256'] = {n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest() for n in
            (*HELPERS, 'install_probe.py', 'install_container_probe.py', 'ci416_dependency_plan.json')}
        end = time.monotonic() + 1200
        report['stage'] = 'target_pull'
        runtime.command(runtime.DOCKER + ['pull', '--quiet', '--platform', 'linux/amd64', runtime.TARGET], end, 240)
        info = runtime.inspect_image(runtime.TARGET, runtime.TARGET_CONFIG, end)
        identity = inventory.registry_identity(runtime.TARGET, info, end)
        if (identity['platform_manifest_digest'] != runtime.TARGET_MANIFEST
                or identity['config_digest'] != runtime.TARGET_CONFIG):
            raise Stop('REGISTRY_MISMATCH')
        report['image'] = identity
        bundle = ('import types, json\n_dependency = types.ModuleType("r27_dependency")\n'
                  + 'exec(' + repr((ROOT / 'dependency_container_probe.py').read_text())
                  + ', _dependency.__dict__)\n_expected = json.loads(' + repr(plan_text) + ')\n'
                  + (ROOT / 'install_container_probe.py').read_text())
        report['stage'] = 'install_and_smoke'
        possible = True
        result = subprocess.run(arguments(runtime, name, run_id), input=bundle, text=True,
            capture_output=True, timeout=min(960, max(1, end - time.monotonic())), check=False)
        report['command'] = {'returncode': result.returncode, 'stdout_bytes': len(result.stdout.encode()),
                             'stderr_bytes': len(result.stderr.encode())}
        if len(result.stdout.encode()) > 262144:
            raise Stop('WORKER_OUTPUT_REJECTED')
        value = json.loads(result.stdout)
        if result.stderr or result.returncode or type(value) is not dict or value.get('status') != worker.SUCCESS:
            report['failure'] = failure(value, worker)
            raise Stop('INSTALL_MEASUREMENT_INCOMPLETE')
        validate(value, expected, worker, dependency_host, dependency)
        report['measurement'] = value
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
    return 0 if report['status'] == 'DEPENDENCIES_INSTALLED_AND_SMOKE_CHECKED' else 3


if __name__ == '__main__':
    raise SystemExit(main())
