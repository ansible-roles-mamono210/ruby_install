#!/usr/bin/env python3
"""One approved actual-variable-file measurement on the fixed lint image."""
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
SUCCESS = 'REAL_VARIABLE_SOURCE_CONTROLS_VERIFIED'
SOURCE_HASH = '88d24996f3151be82a521e162d1ff41d5528b299d3eba643d87628c97fd68c94'
IMAGE = 'ghcr.io/docker-images-mamono210/circleci-executors/ansible-lint@sha256:4ea7fe7ebbe7fd06bd5a7fc61b8931c3303a11c9bd4eb06431a810f5914b8718'
MANIFEST = IMAGE.split('@')[1]
CONFIG = 'sha256:6c9840055142fed835f989805e79182a84d72f53c03805cbba63ad53273cb092'
HELPERS = {
    'env_probe.py': '7773d3dfd2a9b4d9f77d1f45ad37c6ce2810752dafaebf57780fdd2089ef80b9',
    'target_probe.py': '8e83350d3a8a36f6f61e202758deb6f7a0313e8d0159a069d7cda19352144b0f',
    'role_vars_container_probe.py': '6f77aeaeba7007f4ceb664ef887d71f916579efb0406623639c025f9d8dd0dfb',
    '../check_role_variable_names.py': 'e7cdc2a66f074d61ce90035f143e3cd356558f569f1b6ed6c7e3e9c62269cd0e',
}


class Stop(Exception):
    pass


def load(name):
    path = ROOT / (name + '.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != HELPERS[name + '.py']:
        raise Stop('HELPER_CHANGED')
    spec = importlib.util.spec_from_file_location('r47_' + name.replace('../', ''), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def payload(snapshot):
    load('role_vars_container_probe')
    load('../check_role_variable_names')
    checker = (ROOT.parent / 'check_role_variable_names.py').read_text()
    worker = (ROOT / 'role_vars_container_probe.py').read_text()
    return ('import types\nchecker = types.ModuleType("role_file_checker")\n'
            + 'exec(' + repr(checker) + ', checker.__dict__)\n'
            + worker + '\nSNAPSHOT = ' + repr(snapshot) + '\nSOURCE_HASH = ' + repr(SOURCE_HASH) + '''
try:
    need(os.environ.get('RUBY_P1_ROLE_VARS') == 'r47', 'WORKER_ISOLATION')
    print(json.dumps(run(checker, SNAPSHOT, SOURCE_HASH, isolated=True), sort_keys=True))
except Stop as error:
    print(json.dumps({'status': 'INCOMPLETE', 'reason': str(error) if str(error) in REASONS else 'WORKER_CHECK_FAILED'}))
    raise SystemExit(3)
except BaseException:
    print(json.dumps({'status': 'INCOMPLETE', 'reason': 'WORKER_CHECK_FAILED'}))
    raise SystemExit(3)
''')


def arguments(target, name, run_id):
    return target.DOCKER + [
        'run', '--rm', '--pull=never', '--platform', 'linux/amd64',
        '--name', name, '--label', 'ruby-p1.run=' + run_id,
        '--network', 'none', '--read-only', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--no-healthcheck', '--user', 'circleci',
        '--pids-limit', '128', '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=128m,mode=1777', '--workdir', '/tmp',
        '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'RUBY_P1_ROLE_VARS=r47',
        '--entrypoint', 'python3', '-i', CONFIG, '-B', '-',
    ]


def inspect_image(target, deadline):
    fmt = ('{"id":{{json .Id}},"repo_digests":{{json .RepoDigests}},'
           '"os":{{json .Os}},"arch":{{json .Architecture}},'
           '"volumes":{{json .Config.Volumes}},"user":{{json .Config.User}}}')
    info = json.loads(target.command(target.DOCKER + ['image', 'inspect', '--format', fmt, IMAGE],
                                     deadline=deadline, diagnostic_label='IMAGE_INSPECT'))
    if (type(info) is not dict or set(info) != {'id', 'repo_digests', 'os', 'arch', 'volumes', 'user'}
            or info['id'] != CONFIG or info['os'] != 'linux' or info['arch'] != 'amd64'
            or info['volumes'] not in (None, {}) or info['user'] != 'circleci'
            or type(info['repo_digests']) is not list or IMAGE not in info['repo_digests']
            or not all(type(value) is str for value in info['repo_digests'])):
        raise Stop('IMAGE_IDENTITY_MISMATCH')
    return info


def validate(row):
    worker = load('role_vars_container_probe')
    fixed = {'schema': worker.SCHEMA, 'status': SUCCESS,
             'scope': 'actual_defaults_vars_bytes_and_controls', 'arch': 'x86_64',
             'isolation_checked': True, 'temporary_directory_removed': True,
             'source_inputs_unchanged': True, 'actual_source_lint_passed': False,
             'full_role_lint_passed': False, 'phase1_complete': False,
             'source_sha256': {'defaults/main.yml': SOURCE_HASH}}
    if (type(row) is not dict or set(row) != set(fixed) | {'cases', 'packages', 'python', 'uid', 'elapsed_seconds'}
            or any(type(row[k]) is not type(v) or row[k] != v for k, v in fixed.items())
            or type(row['uid']) is not int or row['uid'] <= 0
            or type(row['python']) is not str or not re.fullmatch(r'3\.14\.[0-9]+', row['python'])
            or type(row['packages']) is not dict or set(row['packages']) != set(worker.PACKAGES)
            or row['packages']['ansible-lint'] != '26.1.1'
            or not all(type(v) is str and re.fullmatch('[0-9A-Za-z.+-]{1,40}', v) for v in row['packages'].values())
            or type(row['elapsed_seconds']) not in (int, float) or not math.isfinite(row['elapsed_seconds'])
            or not 0 <= row['elapsed_seconds'] <= 180
            or type(row['cases']) is not list or len(row['cases']) != len(worker.EXPECTED)):
        raise Stop('WORKER_SCHEMA')
    for actual, (name, code, expected) in zip(row['cases'], worker.EXPECTED):
        if type(actual) is not dict or set(actual) != {'case', 'result'} or actual['case'] != name:
            raise Stop('WORKER_CASE_MATRIX')
        result = actual['result']
        if code == 3:
            if json.dumps(result, sort_keys=True) != json.dumps(
                    {'status': 'INCOMPLETE', 'reason': expected, 'exit_code': 3}, sort_keys=True):
                raise Stop('WORKER_CASE_MATRIX')
            continue
        flags = {'schema': 'ruby-role-variable-check-r47', 'status': 'VIOLATIONS_FOUND' if code else 'PASSED',
                 'exit_code': code, 'staged_inputs_unchanged': True, 'temporary_directory_removed': True,
                 'scope': 'defaults_and_vars_only', 'full_role_lint_passed': False, 'source_inputs_unchanged': True}
        if (type(result) is not dict or set(result) != set(flags) | {'source_sha256', 'diagnostics', 'stdout_sha256', 'stderr_sha256'}
                or any(type(result[k]) is not type(v) or result[k] != v for k, v in flags.items())
                or not all(type(result[k]) is str and re.fullmatch('[0-9a-f]{64}', result[k]) for k in ('stdout_sha256', 'stderr_sha256'))
                or type(result['source_sha256']) is not dict
                or set(result['source_sha256']) != ({'defaults/main.yml', 'vars/nested/check.yml'} if name in ('nested_variable', 'uppercase') else {'defaults/main.yml'})
                or not all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v) for v in result['source_sha256'].values())
                or type(result['diagnostics']) is not list or len(result['diagnostics']) != len(expected)):
            raise Stop('WORKER_CASE_MATRIX')
        if name == 'actual_source' and result['source_sha256'] != {'defaults/main.yml': SOURCE_HASH}:
            raise Stop('WORKER_CASE_MATRIX')
        variables = list(worker.RENAMES) if name == 'actual_source' else ['_probe' if name == 'nested_variable' else 'ruby_install_Bad']
        path = 'defaults/main.yml' if name == 'actual_source' else 'vars/nested/check.yml'
        for index, (diagnostic, rule) in enumerate(zip(result['diagnostics'], expected)):
            message = ('Variables names from within roles should use ruby_install_ as a prefix.'
                       if rule == 'var-naming[no-role-prefix]' else
                       'Variables names should match ^[a-z_][a-z0-9_]*$ regex. (' + variables[index] + ')')
            want = {'rule': rule, 'path': path, 'description': message + ' (vars: ' + variables[index] + ')',
                    'location': {'path': 'roles/ruby_install/' + path,
                                 'positions': {'begin': {'line': index + 2, 'column': 1}}}}
            if json.dumps(diagnostic, sort_keys=True) != json.dumps(want, sort_keys=True):
                raise Stop('WORKER_CASE_MATRIX')


def run_worker(argv, source, deadline):
    timeout = min(180, deadline - time.monotonic())
    if timeout <= 0:
        raise Stop('TIME_LIMIT')
    try:
        process = subprocess.run(argv, input=source, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise Stop('WORKER_TIMEOUT') from None
    if process.stderr or len(process.stdout.encode()) > 65536:
        raise Stop('WORKER_OUTPUT_INVALID')
    try:
        row = json.loads(process.stdout)
    except ValueError:
        raise Stop('WORKER_JSON_INVALID') from None
    if process.returncode:
        worker = load('role_vars_container_probe')
        if (process.returncode != 3 or type(row) is not dict or set(row) != {'status', 'reason'}
                or row['status'] != 'INCOMPLETE' or row['reason'] not in worker.REASONS):
            raise Stop('WORKER_FAILURE_SCHEMA')
        raise Stop('WORKER_' + row['reason'])
    validate(row)
    return row


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    for flag in ('allow-pull', 'ephemeral-ci', 'allow-role-vars'):
        parser.add_argument('--' + flag, action='store_true')
    args = parser.parse_args(argv)
    report = {'schema': 'ruby-p1-role-vars-run-r47', 'status': 'INCOMPLETE', 'stage': 'preflight',
              'scope': 'one_offline_actual_variable_file_check', 'role_verified': False,
              'phase1_complete': False, 'cleanup': {}}
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        print('STOP: OUTPUT_UNAVAILABLE_OR_EXISTS', flush=True)
        return 3
    target, name = None, None
    handlers, run_id = {}, uuid.uuid4().hex
    try:
        def interrupted(*_):
            raise Stop('INTERRUPTED')
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.signal(sig, interrupted)
        if (not all((args.allow_pull, args.ephemeral_ci, args.allow_role_vars))
                or os.environ.get('CIRCLECI') != 'true' or os.environ.get('CIRCLE_BRANCH') != BRANCH
                or not re.fullmatch(r'[0-9a-f]{40}', os.environ.get('CIRCLE_SHA1', ''))
                or platform.system() != 'Linux' or platform.machine() != 'x86_64'):
            raise Stop('EXPLICIT_EPHEMERAL_CI_REQUIRED')
        sock = os.stat('/var/run/docker.sock')
        if not stat.S_ISSOCK(sock.st_mode) or sock.st_uid != 0:
            raise Stop('LOCAL_DOCKER_SOCKET_REQUIRED')
        target, inventory = load('target_probe'), load('env_probe')
        checker = load('../check_role_variable_names')
        snapshot = checker.collect(ROOT.parents[1])
        if set(snapshot) != {'defaults/main.yml'} or hashlib.sha256(
                __import__('base64').b64decode(snapshot['defaults/main.yml'], validate=True)).hexdigest() != SOURCE_HASH:
            raise Stop('SOURCE_BASELINE')
        source = payload(snapshot)
        deadline = time.monotonic() + 360
        report.update(run_id=run_id, started_at=inventory.now(), commit=os.environ['CIRCLE_SHA1'],
                      source_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                     for name in tuple(HELPERS) + ('role_vars_probe.py',)})
        report['stage'] = 'pull'
        print('role-vars: pull fixed lint digest', flush=True)
        target.command(target.DOCKER + ['pull', '--quiet', '--platform', 'linux/amd64', IMAGE],
                       timeout=180, deadline=deadline)
        info = inspect_image(target, deadline)
        registry = inventory.registry_identity(IMAGE, info, deadline)
        if (registry.get('platform_manifest_digest') != MANIFEST or registry.get('config_digest') != CONFIG
                or registry.get('index_digest') is not None):
            raise Stop('REGISTRY_BASELINE_MISMATCH')
        report['registry'] = registry
        report['stage'] = 'actual_variable_files'
        print('role-vars: check actual source and seven controls', flush=True)
        name = 'ruby-p1-' + run_id + '-role-vars-r47'
        report['result'] = run_worker(arguments(target, name, run_id), source, deadline)
        if checker.collect(ROOT.parents[1]) != snapshot:
            raise Stop('SOURCE_CHANGED')
        report['source_inputs_unchanged'] = True
        report['cleanup']['container_removed'] = target.cleanup(name, run_id)
        if not report['cleanup']['container_removed']:
            raise Stop('CLEANUP_UNCONFIRMED')
        report.update(status=SUCCESS, stage='finished')
    except Stop as error:
        report['reason'] = str(error)
        if getattr(error, 'diagnostic', None) is not None:
            report['diagnostic'] = error.diagnostic
    except Exception:
        report['reason'] = 'API_OR_RUNTIME_ERROR'
    finally:
        if target is not None and name is not None and not report['cleanup'].get('container_removed'):
            report['cleanup']['container_removed'] = target.cleanup(name, run_id)
            if not report['cleanup']['container_removed']:
                report.update(status='INCOMPLETE', reason='CLEANUP_UNCONFIRMED')
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        with os.fdopen(fd, 'w') as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write('\n')
    print(report['status'], flush=True)
    return 0 if report['status'] == SUCCESS else 3


if __name__ == '__main__':
    raise SystemExit(main())
