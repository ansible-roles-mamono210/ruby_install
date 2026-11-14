"""One explicitly approved source-acquisition CI run on a disposable VM."""
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
    spec = importlib.util.spec_from_file_location('source_' + name, p)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def arguments(runtime, name, run_id):
    return runtime.DOCKER + ['run', '--rm', '--pull=never', '--platform', 'linux/amd64',
        '--name', name, '--label', 'ruby-p1.run=' + run_id,
        '--network', 'bridge', '--read-only', '--user', '65534:65534',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--no-healthcheck',
        '--pids-limit', '64', '--memory', '512m', '--cpus', '1',
        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=96m,mode=1777',
        '--env', 'RUBY_P1_SOURCE_PROBE=1', '--entrypoint', '/usr/bin/python3',
        '-i', runtime.TARGET_CONFIG, '-I', '-B', '-']


def validate(value, worker):
    expected_keys = {'schema', 'status', 'scope', 'results', 'redirect_policy', 'python',
                     'redirect_fixture_tested', 'ansible_download_verified',
                     'archive_safety_verified', 'build_verified'}
    if (type(value) is not dict or set(value) != expected_keys
            or value['schema'] != 'ruby-p1-source-container-r17'
            or value['status'] != worker.SUCCESS
            or value['scope'] != 'two_fixed_https_urls_no_extraction'
            or value['redirect_policy'] != 'reject_all_for_measurement_only'
            or value['python'] != '3.9.19'):
        raise Stop('WORKER_SCHEMA')
    if any(value[k] is not False for k in ('redirect_fixture_tested', 'ansible_download_verified',
                                          'archive_safety_verified', 'build_verified')):
        raise Stop('SCOPE_MISMATCH')
    if type(value['results']) is not list or len(value['results']) != 2:
        raise Stop('SOURCE_COUNT')
    fields = {'version', 'url', 'expected_sha256', 'http_status', 'redirect', 'bytes',
              'sha256', 'checksum_match', 'elapsed_seconds', 'temporary_file_removed'}
    for row, source in zip(value['results'], worker.SOURCES):
        version, path, checksum = source
        if (type(row) is not dict or set(row) != fields or row['version'] != version
                or row['url'] != 'https://' + worker.HOST + path
                or row['expected_sha256'] != checksum or row['sha256'] != checksum
                or type(row['http_status']) is not int or row['http_status'] != 200
                or row['redirect'] != 'none' or row['checksum_match'] is not True
                or row['temporary_file_removed'] is not True
                or type(row['bytes']) is not int or not 0 < row['bytes'] <= worker.MAX_BYTES
                or type(row['elapsed_seconds']) not in (float, int)
                or not math.isfinite(row['elapsed_seconds']) or not 0 <= row['elapsed_seconds'] <= 330):
            raise Stop('SOURCE_RESULT_MISMATCH')


def failure_summary(value):
    # Keep only bounded categories; never persist raw HTTP headers, body or errors.
    reasons = {'CONTAINER_IDENTITY_MISMATCH', 'NETWORK_OR_TLS_OVERRIDE_PRESENT',
               'SOURCE_NOT_ALLOWED', 'TLS_POLICY_MISMATCH', 'REDIRECT_NOT_FOLLOWED',
               'HTTP_STATUS_UNEXPECTED', 'CONTENT_ENCODING_UNEXPECTED',
               'CONTENT_LENGTH_INVALID', 'DOWNLOAD_TIME_LIMIT', 'DOWNLOAD_TOO_LARGE',
               'BODY_LENGTH_MISMATCH', 'SHA256_MISMATCH',
               'TLS_CERTIFICATE_VERIFICATION_FAILED', 'NETWORK_OR_IO_ERROR', 'UNEXPECTED_ERROR'}
    result = {'reason': value.get('reason') if value.get('reason') in reasons else 'UNCLASSIFIED'}
    rows = value.get('results', [])
    if type(rows) is list and len(rows) <= 2:
        result['observations'] = []
        for row in rows:
            if type(row) is not dict:
                continue
            item = {}
            if row.get('version') in ('3.4.12', '4.0.9'):
                item['version'] = row['version']
            if type(row.get('http_status')) is int and 100 <= row['http_status'] <= 599:
                item['http_status'] = row['http_status']
            if row.get('redirect') in ('none', 'http', 'https', 'relative', 'missing', 'invalid', 'other'):
                item['redirect'] = row['redirect']
            result['observations'].append(item)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    for name in ('allow-pull', 'allow-source-download', 'ephemeral-ci'):
        parser.add_argument('--' + name, action='store_true')
    args = parser.parse_args(argv)
    if (not all((args.allow_pull, args.allow_source_download, args.ephemeral_ci))
            or os.environ.get('CIRCLECI') != 'true' or os.environ.get('CIRCLE_BRANCH') != BRANCH
            or platform.system() != 'Linux' or platform.machine() != 'x86_64'):
        print('STOP: EXPLICIT_EPHEMERAL_CI_REQUIRED')
        return 3
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        print('STOP: OUTPUT_UNAVAILABLE_OR_EXISTS')
        return 3
    report = {'schema': 'ruby-p1-source-run-r17', 'status': 'INCOMPLETE', 'stage': 'preflight',
              'p1_03_complete': False, 'phase1_complete': False, 'cleanup_confirmed': None}
    runtime = None
    possible = False
    run_id = uuid.uuid4().hex
    name = 'ruby-p1-' + run_id + '-source-r17'
    handlers = {}
    try:
        def interrupted(_signum, _frame):
            raise Stop('INTERRUPTED')
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.signal(sig, interrupted)
        runtime, inventory, worker = load('runtime_smoke'), load('env_probe'), load('source_container_probe')
        socket = os.stat('/var/run/docker.sock')
        if not stat.S_ISSOCK(socket.st_mode) or socket.st_uid != 0:
            raise Stop('LOCAL_ROOT_DOCKER_SOCKET_REQUIRED')
        report['started_at'] = inventory.now()
        report['source_sha256'] = {n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest()
                                  for n in (*HELPERS, 'source_probe.py', 'source_container_probe.py')}
        end = time.monotonic() + 600
        report['stage'] = 'target_pull'
        runtime.command(runtime.DOCKER + ['pull', '--quiet', '--platform', 'linux/amd64', runtime.TARGET], end, 240)
        info = runtime.inspect_image(runtime.TARGET, runtime.TARGET_CONFIG, end)
        identity = inventory.registry_identity(runtime.TARGET, info, end)
        if (identity['platform_manifest_digest'] != runtime.TARGET_MANIFEST
                or identity['config_digest'] != runtime.TARGET_CONFIG):
            raise Stop('REGISTRY_MISMATCH')
        report['image'] = identity
        report['stage'] = 'download_fixed_sources'
        possible = True
        remaining = min(330, end - time.monotonic())
        if remaining <= 0:
            raise Stop('TIME_LIMIT')
        result = subprocess.run(arguments(runtime, name, run_id),
                                input=(ROOT / 'source_container_probe.py').read_text(),
                                text=True, capture_output=True, timeout=remaining, check=False)
        report['command'] = {'returncode': result.returncode,
                             'stdout_bytes': len(result.stdout.encode()),
                             'stderr_bytes': len(result.stderr.encode())}
        if result.stderr or len(result.stdout.encode()) > 32768:
            raise Stop('WORKER_OUTPUT_REJECTED')
        value = json.loads(result.stdout)
        if type(value) is not dict:
            raise Stop('WORKER_SCHEMA')
        if value.get('status') != worker.SUCCESS:
            report['failure'] = failure_summary(value)
            raise Stop('SOURCE_MEASUREMENT_INCOMPLETE')
        validate(value, worker)
        if result.returncode != 0:
            raise Stop('WORKER_EXIT_MISMATCH')
        report.update(status=worker.SUCCESS, stage='finished', measurement=value)
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
    return 0 if report['status'] == 'SOURCE_DOWNLOADS_AND_SHA256_PASSED' else 3


if __name__ == '__main__':
    raise SystemExit(main())
