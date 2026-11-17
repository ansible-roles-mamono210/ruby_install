#!/usr/bin/env python3
"""One explicitly approved offline live-TLS measurement on the fixed CS9 image."""
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
SUCCESS = 'LIVE_TLS_ACQUISITION_GUARDS_VERIFIED'
HELPERS = {
    'env_probe.py': '7773d3dfd2a9b4d9f77d1f45ad37c6ce2810752dafaebf57780fdd2089ef80b9',
    'target_probe.py': '8e83350d3a8a36f6f61e202758deb6f7a0313e8d0159a069d7cda19352144b0f',
    'source_container_probe.py': 'd264f2d1cb6cfbaf7c8b4f9d8530e2e3586a99ec9abf8e73d12a48ab1dad35a8',
    'build_container_probe.py': 'adc25df0317a8eaef0531a2b343b0a46d2c90773f36f7efa2db39e587008174d',
    'download_guard_fixture.py': '2efaa5cf40127ed5421eab9a16e7e2925d46de5087dacde890ad02672f703896',
}


class Stop(Exception):
    pass


def load(name):
    path = ROOT / (name + '.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != HELPERS[path.name]:
        raise Stop('HELPER_CHANGED')
    spec = importlib.util.spec_from_file_location('r44_' + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def payload(cert, key):
    for name, digest in HELPERS.items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise Stop('HELPER_CHANGED')
    source = (ROOT / 'source_container_probe.py').read_text()
    build = (ROOT / 'build_container_probe.py').read_text()
    worker = (ROOT / 'download_guard_fixture.py').read_text()
    # Ephemeral TLS identity is carried only in stdin; never argv, Env, logs or artifacts.
    return worker + '\n' + '\n'.join([
        'try:',
        "    need(os.environ.get('RUBY_P1_DOWNLOAD_GUARD') == 'r44' and os.geteuid() == 65534, 'WORKER_IDENTITY')",
        "    need(platform.machine() == 'x86_64' and platform.python_version() == '3.9.19', 'WORKER_PLATFORM')",
        "    release = Path('/etc/os-release').read_text()",
        "    need('ID=\"centos\"' in release and 'VERSION_ID=\"9\"' in release, 'WORKER_OS')",
        "    need({name for _, name in socket.if_nameindex()} == {'lo'} and bool(os.statvfs('/').f_flag & os.ST_RDONLY) and bool(os.statvfs('/tmp').f_flag & os.ST_NOEXEC), 'WORKER_ISOLATION')",
        '    result = exercise(' + repr(source) + ', ' + repr(build) + ', ' + repr(cert) + ', ' + repr(key) + ')',
        "    result['platform'] = {'os': 'centos-stream-9', 'arch': 'x86_64', 'uid': 65534}",
        '    print(json.dumps(result, sort_keys=True))',
        'except Stop as error:',
        "    reason = str(error) if str(error) in REASONS else 'WORKER_CHECK_FAILED'",
        "    print(json.dumps({'status': 'INCOMPLETE', 'reason': reason}))",
        '    raise SystemExit(3)',
        'except BaseException:',
        "    print(json.dumps({'status': 'INCOMPLETE', 'reason': 'WORKER_CHECK_FAILED'}))",
        '    raise SystemExit(3)',
        '',
    ])


def arguments(target, name, run_id):
    return target.DOCKER + [
        'run', '--rm', '--pull=never', '--platform', 'linux/amd64',
        '--name', name, '--label', 'ruby-p1.run=' + run_id,
        '--network', 'none', '--read-only', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--no-healthcheck', '--user', '65534:65534',
        '--pids-limit', '64', '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777',
        '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'RUBY_P1_DOWNLOAD_GUARD=r44',
        '--entrypoint', '/usr/bin/python3', '-i', target.CONFIG, '-I', '-B', '-',
    ]


def validate(row):
    fixture = load('download_guard_fixture')
    expected = {'schema': fixture.SCHEMA, 'status': SUCCESS, 'python': '3.9.19',
                'scope': 'unchanged_p1_download_functions_with_fixture_endpoint_ca_and_checksum',
                'tls_certificate_and_hostname_checks': True, 'sink_positive_controls': True,
                'temporary_directory_removed': True, 'redirect_policy': 'reject_all_candidate_only',
                'role_verified': False, 'full_build_entrypoint_executed': False,
                'p1_04_complete': False, 'phase1_complete': False,
                'platform': {'os': 'centos-stream-9', 'arch': 'x86_64', 'uid': 65534}}
    if (type(row) is not dict or set(row) != set(expected) | {'cases', 'elapsed_seconds'}
            or any(type(row[k]) is not type(v) or row[k] != v for k, v in expected.items())
            or type(row['elapsed_seconds']) not in (int, float)
            or not math.isfinite(row['elapsed_seconds']) or not 0 <= row['elapsed_seconds'] <= 60):
        raise Stop('WORKER_SCHEMA')
    cases = []
    for kind in ('source', 'build'):
        matrix = [('valid', 200, 'ACCEPTED', 1), ('checksum_mismatch', 200, 'SHA256_MISMATCH', 0)]
        matrix += [(scheme + '_redirect', status,
                    'REDIRECT_NOT_FOLLOWED' if kind == 'source' else 'SOURCE_HTTP_STATUS_OR_REDIRECT', 0)
                   for scheme in ('http', 'https') for status in fixture.REDIRECTS]
        matrix += [(case, 200, 'TLS_CERTIFICATE_REJECTED', 0)
                   for case in ('untrusted_certificate', 'hostname_mismatch')]
        for case, status, outcome, audit in matrix:
            cases.append({'helper': kind, 'case': case, 'response_status': status, 'outcome': outcome,
                          'audit_calls': audit, 'connection_factory_calls': 1,
                          'sink_delta': {x: {'connections': 0, 'requests': 0} for x in ('http', 'https')}})
    # Canonical JSON distinguishes bool from int and rejects additional fields.
    if json.dumps(row['cases'], sort_keys=True) != json.dumps(cases, sort_keys=True):
        raise Stop('WORKER_CASE_MATRIX')


def run_worker(argv, source, deadline):
    timeout = min(60, deadline - time.monotonic())
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
        allowed = load('download_guard_fixture').REASONS + ('WORKER_CHECK_FAILED',)
        if (process.returncode == 3 and type(row) is dict and set(row) == {'status', 'reason'}
                and row['status'] == 'INCOMPLETE' and row['reason'] in allowed):
            raise Stop('WORKER_' + row['reason'])
        raise Stop('WORKER_FAILURE_SCHEMA')
    validate(row)
    return row


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    for flag in ('allow-pull', 'ephemeral-ci', 'allow-live-tls-fixture'):
        parser.add_argument('--' + flag, action='store_true')
    args = parser.parse_args(argv)
    report = {'schema': 'ruby-p1-download-guard-run-r44', 'status': 'INCOMPLETE', 'stage': 'preflight',
              'scope': 'one_offline_disposable_target_container', 'role_verified': False,
              'p1_04_complete': False, 'phase1_complete': False, 'cleanup': {}}
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        print('STOP: OUTPUT_UNAVAILABLE_OR_EXISTS', flush=True)
        return 3
    target, name = None, None
    handlers = {}
    run_id = uuid.uuid4().hex
    try:
        def interrupted(*_):
            raise Stop('INTERRUPTED')
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.signal(sig, interrupted)
        if (not all((args.allow_pull, args.ephemeral_ci, args.allow_live_tls_fixture))
                or os.environ.get('CIRCLECI') != 'true' or os.environ.get('CIRCLE_BRANCH') != BRANCH
                or not re.fullmatch(r'[0-9a-f]{40}', os.environ.get('CIRCLE_SHA1', ''))
                or platform.system() != 'Linux' or platform.machine() != 'x86_64'):
            raise Stop('EXPLICIT_EPHEMERAL_CI_REQUIRED')
        sock = os.stat('/var/run/docker.sock')
        if not stat.S_ISSOCK(sock.st_mode) or sock.st_uid != 0:
            raise Stop('LOCAL_DOCKER_SOCKET_REQUIRED')
        fixture = load('download_guard_fixture')
        target, inventory = load('target_probe'), load('env_probe')
        cert, key = fixture.certificate_material()
        source = payload(cert, key)
        del cert, key
        deadline = time.monotonic() + 300
        report.update(run_id=run_id, started_at=inventory.now(), commit=os.environ['CIRCLE_SHA1'],
                      source_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                     for name in tuple(HELPERS) + ('download_guard_probe.py',)})
        report['stage'] = 'pull'
        print('download-guard: pull fixed target digest', flush=True)
        target.command(target.DOCKER + ['pull', '--quiet', '--platform', 'linux/amd64', target.TARGET],
                       timeout=180, deadline=deadline)
        info = target.inspect_image(deadline)
        registry = inventory.registry_identity(target.TARGET, info, deadline)
        if registry.get('platform_manifest_digest') != target.MANIFEST or registry.get('config_digest') != target.CONFIG:
            raise Stop('REGISTRY_BASELINE_MISMATCH')
        report['registry'] = registry
        report['stage'] = 'live_tls_fixture'
        print('download-guard: run 32 live loopback TLS cases', flush=True)
        name = 'ruby-p1-' + run_id + '-download-r44'
        report['result'] = run_worker(arguments(target, name, run_id), source, deadline)
        del source
        report['cleanup']['container_removed'] = target.cleanup(name, run_id)
        if not report['cleanup']['container_removed']:
            raise Stop('CLEANUP_UNCONFIRMED')
        report.update(status=SUCCESS, stage='finished')
    except Stop as error:
        report['reason'] = str(error)
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
