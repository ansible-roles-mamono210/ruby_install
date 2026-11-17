#!/usr/bin/env python3
"""One approved offline exec/noexec pair on the existing fixed target image."""
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
SUCCESS = 'EXEC_AND_NOEXEC_BOUNDARIES_VERIFIED'
HELPERS = {
    'env_probe.py': '7773d3dfd2a9b4d9f77d1f45ad37c6ce2810752dafaebf57780fdd2089ef80b9',
    'target_probe.py': '8e83350d3a8a36f6f61e202758deb6f7a0313e8d0159a069d7cda19352144b0f',
    'build_container_probe.py': 'adc25df0317a8eaef0531a2b343b0a46d2c90773f36f7efa2db39e587008174d',
    'noexec_container_probe.py': 'e2ff0c1924652dffb1ff323bf7889b9f930f4a50e4a987b9ad1a9fcf3e4053ce',
}
MODES = ('exec', 'noexec')


class Stop(Exception):
    pass


def load(name):
    path = ROOT / (name + '.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != HELPERS[path.name]:
        raise Stop('HELPER_CHANGED')
    spec = importlib.util.spec_from_file_location('r40_' + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def payload():
    for name, digest in HELPERS.items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise Stop('HELPER_CHANGED')
    text = 'import types\n_build = types.ModuleType("r40_fixed_r39_build")\n'
    text += 'exec(' + repr((ROOT / 'build_container_probe.py').read_text()) + ', _build.__dict__)\n'
    return text + (ROOT / 'noexec_container_probe.py').read_text()


def arguments(target, name, run_id, mode):
    if mode not in MODES:
        raise Stop('MODE_INVALID')
    return target.DOCKER + [
        'run', '--rm', '--pull=never', '--platform', 'linux/amd64',
        '--name', name, '--label', 'ruby-p1.run=' + run_id,
        '--network', 'none', '--read-only', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--no-healthcheck',
        '--user', '0:0', '--pids-limit', '64', '--memory', '512m',
        '--memory-swap', '512m', '--cpus', '1',
        '--tmpfs', '/tmp:rw,nosuid,nodev,' + mode + ',size=32m,mode=1777',
        '--env', 'PYTHONDONTWRITEBYTECODE=1',
        '--env', 'RUBY_P1_NOEXEC_PROBE=r40', '--env', 'RUBY_P1_BUILD_PROBE=r39',
        '--env', 'RUBY_P1_NOEXEC_MODE=' + mode,
        '--entrypoint', '/usr/bin/python3', '-i', target.CONFIG, '-I', '-B', '-',
    ]


def digest(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def number(value, maximum):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum


def validate(row, mode):
    keys = {'schema', 'status', 'stage', 'scope', 'role_verified',
            'full_build_entrypoint_executed', 'p1_04_complete', 'phase1_complete',
            'mode', 'platform', 'mount', 'preflight', 'guard_state', 'execution',
            'fixture_directory_empty', 'mount_table_unchanged', 'elapsed_seconds'}
    noexec = mode == 'noexec'
    if (type(row) is not dict or set(row) != keys
            or row['schema'] != 'ruby-p1-noexec-container-r40'
            or row['status'] != 'NOEXEC_FIXTURE_VERIFIED' or row['stage'] != 'finished'
            or row['scope'] != 'fixed_tmp_mount_and_build_preflight_only' or row['mode'] != mode
            or row['platform'] != {'os': 'centos-stream-9', 'arch': 'x86_64', 'python': '3.9.19'}
            or any(row[key] is not False for key in ('role_verified', 'full_build_entrypoint_executed',
                                                    'p1_04_complete', 'phase1_complete'))
            or any(row[key] is not True for key in ('fixture_directory_empty', 'mount_table_unchanged'))
            or not number(row['elapsed_seconds'], 60)):
        raise Stop('WORKER_SCHEMA')
    mount = row['mount']
    if (type(mount) is not dict or set(mount) != {'path', 'filesystem', 'mountinfo_noexec',
            'statvfs_noexec', 'read_only', 'nosuid', 'nodev'} or mount['path'] != '/tmp'
            or mount['filesystem'] != 'tmpfs' or mount['mountinfo_noexec'] is not noexec
            or mount['statvfs_noexec'] is not noexec or mount['read_only'] is not False
            or mount['nosuid'] is not True or mount['nodev'] is not True):
        raise Stop('WORKER_MOUNT')
    guard = row['preflight']
    if (type(guard) is not dict or set(guard) != {'called', 'reason'}
            or guard['called'] is not noexec
            or guard['reason'] != ('WORKSPACE_NOEXEC' if noexec else 'NOT_RUN_ON_EXEC_CONTROL')):
        raise Stop('WORKER_GUARD')
    state = row['guard_state']
    if (type(state) is not dict or set(state) != {'before', 'after', 'unchanged'}
            or state['unchanged'] is not True or state['before'] != state['after']):
        raise Stop('WORKER_STATE')
    for record in (state['before'], state['after']):
        if (type(record) is not dict or set(record) != {'sha256', 'entries', 'file_bytes'}
                or not digest(record['sha256']) or type(record['entries']) is not int
                or not 6 <= record['entries'] <= 1024 or type(record['file_bytes']) is not int
                or not 0 <= record['file_bytes'] <= 128 * 1024 ** 2):
            raise Stop('WORKER_STATE')
    execution = row['execution']
    if (type(execution) is not dict or set(execution) != {'outcome', 'errno', 'returncode',
            'stdout_bytes', 'stderr_bytes', 'binary_sha256', 'binary_bytes', 'fixture_removed'}
            or execution['outcome'] != ('EACCES' if noexec else 'EXECUTED')
            or execution['fixture_removed'] is not True or not digest(execution['binary_sha256'])
            or type(execution['binary_bytes']) is not int or not 64 <= execution['binary_bytes'] <= 1024 ** 2
            or any(type(execution[key]) is not int or execution[key] != 0
                   for key in ('stdout_bytes', 'stderr_bytes'))
            or (noexec and (type(execution['errno']) is not int or execution['errno'] != 13
                            or execution['returncode'] is not None))
            or (not noexec and (execution['errno'] is not None
                                or type(execution['returncode']) is not int or execution['returncode'] != 0))):
        raise Stop('WORKER_EXECUTION')


def run_worker(target, argv, source, deadline):
    timeout = min(60, deadline - time.monotonic())
    if timeout <= 0:
        raise Stop('TIME_LIMIT')
    try:
        process = subprocess.run(argv, input=source, capture_output=True, text=True,
                                 timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise Stop('WORKER_TIMEOUT') from None
    if process.stderr or len(process.stdout.encode()) > 65536:
        raise Stop('WORKER_OUTPUT_INVALID')
    try:
        row = json.loads(process.stdout)
    except ValueError:
        raise Stop('WORKER_JSON_INVALID') from None
    if process.returncode:
        # Preserve only an enumerated stage; no exception text, URLs or arbitrary values.
        stage = row.get('stage') if type(row) is dict else None
        if stage not in ('identity', 'mount', 'preflight', 'kernel_execution'):
            stage = 'unknown'
        raise Stop('WORKER_FAILED_' + stage.upper())
    return row


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    for name in ('allow-pull', 'ephemeral-ci', 'allow-noexec-fixture'):
        parser.add_argument('--' + name, action='store_true')
    args = parser.parse_args(argv)
    report = {'schema': 'ruby-p1-noexec-run-r40', 'status': 'INCOMPLETE', 'stage': 'preflight',
              'scope': 'two_sequential_offline_disposable_target_containers',
              'role_verified': False, 'p1_04_complete': False, 'phase1_complete': False,
              'results': [], 'cleanup': {}}
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        print('STOP: OUTPUT_UNAVAILABLE_OR_EXISTS', flush=True)
        return 3
    possible = []
    target = None
    handlers = {}
    run_id = uuid.uuid4().hex
    try:
        def interrupted(*_):
            raise Stop('INTERRUPTED')
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.signal(sig, interrupted)
        if (not all((args.allow_pull, args.ephemeral_ci, args.allow_noexec_fixture))
                or os.environ.get('CIRCLECI') != 'true' or os.environ.get('CIRCLE_BRANCH') != BRANCH
                or not re.fullmatch(r'[0-9a-f]{40}', os.environ.get('CIRCLE_SHA1', ''))
                or platform.system() != 'Linux' or platform.machine() != 'x86_64'):
            raise Stop('EXPLICIT_EPHEMERAL_CI_REQUIRED')
        sock = os.stat('/var/run/docker.sock')
        if not stat.S_ISSOCK(sock.st_mode) or sock.st_uid != 0:
            raise Stop('LOCAL_DOCKER_SOCKET_REQUIRED')
        source = payload()
        target, inventory = load('target_probe'), load('env_probe')
        deadline = time.monotonic() + 300
        report.update(run_id=run_id, started_at=inventory.now(), commit=os.environ['CIRCLE_SHA1'],
                      source_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                     for name in tuple(HELPERS) + ('noexec_probe.py',)})
        report['stage'] = 'pull'
        print('noexec: pull the fixed target digest', flush=True)
        target.command(target.DOCKER + ['pull', '--quiet', '--platform', 'linux/amd64', target.TARGET],
                       timeout=180, deadline=deadline)
        info = target.inspect_image(deadline)
        registry = inventory.registry_identity(target.TARGET, info, deadline)
        if registry.get('platform_manifest_digest') != target.MANIFEST or registry.get('config_digest') != target.CONFIG:
            raise Stop('REGISTRY_BASELINE_MISMATCH')
        report['registry'] = registry
        for mode in MODES:
            report['stage'] = mode
            print('noexec: run ' + mode + ' fixture', flush=True)
            name = 'ruby-p1-' + run_id + '-noexec-r40-' + mode
            possible.append((name, mode))
            row = run_worker(target, arguments(target, name, run_id, mode), source, deadline)
            validate(row, mode)
            report['results'].append(row)
            if not target.cleanup(name, run_id):
                raise Stop('CLEANUP_UNCONFIRMED')
            report['cleanup'][mode] = True
        if len({row['execution']['binary_sha256'] for row in report['results']}) != 1:
            raise Stop('CONTROL_BINARY_MISMATCH')
        report.update(status=SUCCESS, stage='finished', same_binary_verified=True)
    except Stop as error:
        report['reason'] = str(error)
    except Exception:
        report['reason'] = 'API_OR_RUNTIME_ERROR'
    finally:
        if target is not None:
            for name, mode in possible:
                if report['cleanup'].get(mode) is not True:
                    report['cleanup'][mode] = target.cleanup(name, run_id)
            if not all(report['cleanup'].values()):
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
