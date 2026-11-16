#!/usr/bin/env python3
"""r34 host: one approved CI430-matched Rust installation on disposable CI."""
import argparse
import hashlib
import importlib.util
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
BRANCH = 'plan/ruby-100-p1-env-r1'
PACKAGES = ('gcc', 'make', 'tar', 'gzip', 'ca-certificates', 'openssl-devel',
            'libyaml-devel', 'zlib-devel', 'libffi-devel', 'rust')
HELPERS = {'runtime_smoke.py': '450a33babab510d9d529e309cbfd0ea1a9d76ef4728f1e6190a6a0f41935ecc5', 'env_probe.py': '7773d3dfd2a9b4d9f77d1f45ad37c6ce2810752dafaebf57780fdd2089ef80b9', 'dependency_probe.py': '240c2304eb28c8d769cb6d5cfaf2ae964175e50339d9debf358e7331a8807018', 'dependency_container_probe.py': '2118deac29ca85c050e4cee8291b3a062f7d9646fe0c69739562794922904b1d', 'install_probe.py': 'e22b2ee47ba07e88260d1e5877d08acfdfdcaa030f2eea4f98ffb470ad273ab5', 'install_container_probe.py': 'a6e0acd458cc03ba90bccb552f735957681c73852f3e0d80cee4aac7ed2c9fd9', 'rust_install_container_probe.py': 'de4dd9186d6da8ca69ae821aab5169e637b17c130d9e8d104f76a9fe589c2a0a', 'ci430_dependency_plan.json': '530c9e7b9f3d6ac0a674878a7c4acdca4fd1118a43d0ffa40fa4ebc64d8ab847'}


class Stop(Exception):
    pass


def verified_text(name):
    data = (ROOT / name).read_bytes()
    if name not in HELPERS or hashlib.sha256(data).hexdigest() != HELPERS[name]:
        raise Stop('HELPER_CHANGED')
    return data.decode('utf-8')


def load(name):
    verified_text(name + '.py')
    spec = importlib.util.spec_from_file_location('r34_' + name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def profile(dependency):
    if dependency.PACKAGES != PACKAGES[:-1]:
        raise Stop('DEPENDENCY_PROFILE_CHANGED')
    dependency.PACKAGES = PACKAGES
    return dependency


def arguments(runtime, install_host, name, run_id):
    result = install_host.arguments(runtime, name, run_id)
    pos = result.index('--tmpfs')
    del result[pos:pos + 2]
    pos = result.index('RUBY_P1_INSTALL_PROBE=r27')
    result[pos] = 'RUBY_P1_RUST_INSTALL_PROBE=r34'
    pos = result.index('--cpus')
    result[pos:pos] = ['--memory-swap', '2g']
    return result


def bundle(plan_text):
    text = 'import types, json\n'
    for variable, name in (('_dependency', 'dependency_container_probe.py'),
                            ('_installer', 'install_container_probe.py')):
        text += variable + ' = types.ModuleType(' + repr('r34' + variable) + ')\n'
        text += 'exec(' + repr(verified_text(name)) + ', ' + variable + '.__dict__)\n'
    text += '_dependency.PACKAGES = ' + repr(PACKAGES) + '\n'
    text += '_expected = json.loads(' + repr(plan_text) + ')\n'
    return text + verified_text('rust_install_container_probe.py')


def valid_digest(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def number(value, maximum):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum


def validate(value, expected, worker, installer, dependency_host, dependency):
    keys = {'schema', 'status', 'stage', 'rpm_downloaded', 'all_signatures_verified',
            'transaction_started', 'transaction_returned', 'ruby_build_verified',
            'p1_03_complete', 'phase1_complete', 'imported_key_fingerprints',
            'root_free_bytes_before', 'rpm_before', 'configuration_before',
            'substitutions', 'transaction_plan_matches_ci430', 'plan',
            'public_key_file_sha256', 'rpms', 'delta', 'rpm_after',
            'configuration_after', 'candidates_present', 'smoke', 'elapsed_seconds', 'rpm_tsflags',
            'transaction_error_count', 'plan_reference', 'rust_installed', 'rust_compiler_checked',
            'rust_smoke', 'rust_version', 'p1_04_complete'}
    if (type(value) is not dict or set(value) != keys or value['schema'] != worker.SCHEMA
            or value['plan_reference'] != 'CI430'
            or value['status'] != worker.SUCCESS or value['stage'] != 'finished'
            or any(value[k] is not True for k in ('rpm_downloaded', 'all_signatures_verified',
                    'transaction_started', 'transaction_returned', 'transaction_plan_matches_ci430',
                    'rust_installed', 'rust_compiler_checked'))
            or any(value[k] is not False for k in ('ruby_build_verified', 'p1_03_complete', 'p1_04_complete', 'phase1_complete'))
            or value['rpm_before'] != expected['baseline_rpm']
            or value['configuration_before'] != expected['baseline_configuration']
            or value['configuration_after'] != value['configuration_before']
            or value['plan'] != {k: expected[k] for k in ('install_set', 'remove_set')}
            or value['candidates_present'] != list(dependency.PACKAGES)
            or not dependency_host.valid_substitutions(value['substitutions'], dependency, success=True)
            or not number(value['elapsed_seconds'], 960)
            or type(value['root_free_bytes_before']) is not int
            or value['root_free_bytes_before'] < installer.MIN_FREE):
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
            or delta['added_or_upgraded'] != len(expected['install_set']) or delta['replaced_old_versions'] != len(expected['remove_set'])
            or delta['new_package_names'] != 26 or not 0 <= delta['public_keys_added'] <= 4):
        raise Stop('WORKER_SCHEMA')
    after = value['rpm_after']
    if (type(after) is not dict or set(after) != {'count', 'sha256'}
            or type(after['count']) is not int
            or after['count'] != expected['baseline_rpm']['count'] + 26 + delta['public_keys_added'] or not valid_digest(after['sha256'])):
        raise Stop('WORKER_SCHEMA')
    records = value['rpms']
    if type(records) is not list or len(records) != len(expected['install_set']):
        raise Stop('WORKER_SCHEMA')
    for row in records:
        if (type(row) is not dict or set(row) != {'package', 'sha256', 'bytes', 'signature_verified'}
                or row['signature_verified'] is not True or not valid_digest(row['sha256'])
                or type(row['bytes']) is not int or not 0 < row['bytes'] <= installer.MAX_DOWNLOAD):
            raise Stop('WORKER_SCHEMA')
        dependency_host.validate_packages([row['package']], dependency, dependency.REPOS)
    if (sorted((r['package'] for r in records), key=installer.key)
            != sorted(expected['install_set'], key=installer.key)
            or sum(r['bytes'] for r in records) > installer.MAX_DOWNLOAD):
        raise Stop('WORKER_SCHEMA')
    if type(value['smoke']) is not list or len(value['smoke']) != 3:
        raise Stop('WORKER_SCHEMA')
    for item, name in zip(value['smoke'], installer.SMOKE_NAMES):
        if (type(item) is not dict or set(item) != {'name', 'returncode', 'stderr_bytes',
                'output_match', 'elapsed_seconds'} or item['name'] != name
                or type(item['returncode']) is not int or item['returncode'] != 0
                or type(item['stderr_bytes']) is not int or item['stderr_bytes'] != 0
                or item['output_match'] is not True or not number(item['elapsed_seconds'], 95)):
            raise Stop('WORKER_SCHEMA')

    selected = [r for r in expected['install_set'] if r['name'] == 'rust']
    if (len(selected) != 1 or value['rust_version'] !=
            {'release': selected[0]['version'], 'host': worker.RUST_HOST}):
        raise Stop('RUST_VERSION_SCHEMA')
    validate_rust_smoke(value['rust_smoke'], worker)


def validate_rust_smoke(rows, worker):
    if type(rows) is not list or len(rows) != 3:
        raise Stop('RUST_SMOKE_SCHEMA')
    for row, name in zip(rows, worker.RUST_NAMES):
        if (type(row) is not dict or set(row) != {'name', 'returncode', 'stderr_bytes',
                'output_match', 'elapsed_seconds'} or row['name'] != name
                or type(row['returncode']) is not int or row['returncode'] != 0
                or type(row['stderr_bytes']) is not int or row['stderr_bytes'] != 0
                or row['output_match'] is not True or not number(row['elapsed_seconds'], 95)):
            raise Stop('RUST_SMOKE_SCHEMA')


def failure(value, worker, installer):
    result = {'stage': 'UNKNOWN', 'reason': 'UNCLASSIFIED'}
    if type(value) is dict and value.get('schema') == worker.SCHEMA:
        if type(value.get('stage')) is str and value['stage'] in worker.STAGES:
            result['stage'] = value['stage']
        if type(value.get('reason')) is str and value['reason'] in installer.REASONS | {
                'RUST_VERSION', 'RUST_SMOKE_FAILED'}:
            result['reason'] = value['reason']
        for name in ('rpm_downloaded', 'all_signatures_verified', 'transaction_started',
                     'transaction_returned', 'rust_installed', 'rust_compiler_checked'):
            if type(value.get(name)) is bool:
                result[name] = value[name]
        for key, names in (('smoke', installer.SMOKE_NAMES), ('rust_smoke', worker.RUST_NAMES)):
            records = value.get(key)
            if type(records) is list and len(records) <= 3:
                result[key] = [{k: row[k] for k in ('name', 'returncode', 'stderr_bytes', 'output_match')}
                    for row in records if type(row) is dict and type(row.get('name')) is str
                    and row['name'] in names and type(row.get('returncode')) is int
                    and -255 <= row['returncode'] <= 255 and type(row.get('stderr_bytes')) is int
                    and 0 <= row['stderr_bytes'] <= 1048576 and type(row.get('output_match')) is bool]
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    for flag in ('allow-pull', 'allow-rust-install', 'allow-ci430-replacements', 'ephemeral-ci'):
        parser.add_argument('--' + flag, action='store_true')
    args = parser.parse_args(argv)
    if (not all((args.allow_pull, args.allow_rust_install, args.allow_ci430_replacements, args.ephemeral_ci))
            or os.environ.get('CIRCLECI') != 'true' or os.environ.get('CIRCLE_BRANCH') != BRANCH
            or platform.system() != 'Linux' or platform.machine() != 'x86_64'):
        print('STOP: EXPLICIT_EPHEMERAL_RUST_INSTALL_APPROVAL_REQUIRED')
        return 3
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        print('STOP: OUTPUT_UNAVAILABLE_OR_EXISTS')
        return 3
    report = {'schema': 'ruby-p1-rust-install-run-r34', 'status': 'INCOMPLETE', 'stage': 'preflight',
              'p1_03_complete': False, 'p1_04_complete': False, 'phase1_complete': False,
              'rust_installed': False, 'rust_compiler_checked': False, 'ruby_build_verified': False,
              'cleanup_confirmed': None, 'plan_reference': 'CI430'}
    possible, runtime, handlers = False, None, {}
    run_id = uuid.uuid4().hex
    name = 'ruby-p1-' + run_id + '-rust-install-r34'
    try:
        def interrupted(_sig, _frame):
            raise Stop('INTERRUPTED')
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.signal(sig, interrupted)
        runtime, inventory = load('runtime_smoke'), load('env_probe')
        worker, installer, install_host = load('rust_install_container_probe'), load('install_container_probe'), load('install_probe')
        dependency_host, dependency = load('dependency_probe'), profile(load('dependency_container_probe'))
        plan_text = verified_text('ci430_dependency_plan.json')
        expected = json.loads(plan_text)
        script = bundle(plan_text)
        socket = os.stat('/var/run/docker.sock')
        if not stat.S_ISSOCK(socket.st_mode) or socket.st_uid != 0:
            raise Stop('LOCAL_ROOT_DOCKER_SOCKET_REQUIRED')
        report['started_at'] = inventory.now()
        report['source_sha256'] = {n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest()
                                  for n in (*HELPERS, 'rust_install_probe.py')}
        end = time.monotonic() + 1200
        report['stage'] = 'target_pull'
        runtime.command(runtime.DOCKER + ['pull', '--quiet', '--platform', 'linux/amd64', runtime.TARGET], end, 240)
        info = runtime.inspect_image(runtime.TARGET, runtime.TARGET_CONFIG, end)
        identity = inventory.registry_identity(runtime.TARGET, info, end)
        if (identity['platform_manifest_digest'] != runtime.TARGET_MANIFEST
                or identity['config_digest'] != runtime.TARGET_CONFIG):
            raise Stop('REGISTRY_MISMATCH')
        report['image'] = identity
        report['stage'] = 'install_and_rust_smoke'
        remaining = min(960, end - time.monotonic())
        if remaining <= 0:
            raise Stop('TIME_LIMIT')
        possible = True
        result = subprocess.run(arguments(runtime, install_host, name, run_id), input=script,
                                text=True, capture_output=True, timeout=remaining, check=False)
        report['command'] = {'returncode': result.returncode, 'stdout_bytes': len(result.stdout.encode()),
                             'stderr_bytes': len(result.stderr.encode())}
        if len(result.stdout.encode()) > 262144:
            raise Stop('WORKER_OUTPUT_REJECTED')
        value = json.loads(result.stdout)
        if result.stderr or result.returncode or type(value) is not dict or value.get('status') != worker.SUCCESS:
            report['failure'] = failure(value, worker, installer)
            raise Stop('RUST_INSTALL_INCOMPLETE')
        validate(value, expected, worker, installer, dependency_host, dependency)
        report['measurement'] = value
        report.update(status=worker.SUCCESS, stage='finished', rust_installed=True, rust_compiler_checked=True)
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
    return 0 if report['status'] == 'RUST_INSTALLED_AND_COMPILER_CHECKED' else 3


if __name__ == '__main__':
    raise SystemExit(main())
