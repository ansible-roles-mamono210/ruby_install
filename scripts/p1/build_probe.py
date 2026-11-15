#!/usr/bin/env python3
"""Host boundary for one explicitly approved Ruby 4.0.9 evaluation build."""
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
# Refreshed only when preparing a reviewed proposal, never at runtime.
HELPERS = {'runtime_smoke.py': '450a33babab510d9d529e309cbfd0ea1a9d76ef4728f1e6190a6a0f41935ecc5', 'env_probe.py': '7773d3dfd2a9b4d9f77d1f45ad37c6ce2810752dafaebf57780fdd2089ef80b9', 'dependency_probe.py': '240c2304eb28c8d769cb6d5cfaf2ae964175e50339d9debf358e7331a8807018', 'dependency_container_probe.py': '2118deac29ca85c050e4cee8291b3a062f7d9646fe0c69739562794922904b1d', 'install_probe.py': 'e22b2ee47ba07e88260d1e5877d08acfdfdcaa030f2eea4f98ffb470ad273ab5', 'install_container_probe.py': 'a6e0acd458cc03ba90bccb552f735957681c73852f3e0d80cee4aac7ed2c9fd9', 'source_container_probe.py': 'd264f2d1cb6cfbaf7c8b4f9d8530e2e3586a99ec9abf8e73d12a48ab1dad35a8', 'build_container_probe.py': '440320dd8c0782e1bd07bae0374b1d58f25cc71dac634a3276e032610d4eb6b5'}


class Stop(Exception):
    pass


def load(name):
    path = ROOT / (name + '.py')
    if path.name not in HELPERS or hashlib.sha256(path.read_bytes()).hexdigest() != HELPERS[path.name]:
        raise Stop('HELPER_CHANGED')
    spec = importlib.util.spec_from_file_location('r31_' + name, path)
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
    # /tmp stays on the disposable container layer; no 1 GiB RAM-backed build workspace.
    return result + ['--security-opt', 'no-new-privileges', '--no-healthcheck',
        '--pids-limit', '128', '--memory', '2g', '--memory-swap', '2g', '--cpus', '1',
        '--env', 'RUBY_P1_BUILD_PROBE=r31', '--entrypoint', '/usr/bin/python3',
        '-i', runtime.TARGET_CONFIG, '-I', '-B', '-']


def bundle(plan_text):
    text = 'import types, json\n'
    for variable, name in (('_dependency', 'dependency_container_probe.py'),
                            ('_installer', 'install_container_probe.py'),
                            ('_source', 'source_container_probe.py')):
        text += variable + ' = types.ModuleType(' + repr('r31' + variable) + ')\n'
        text += 'exec(' + repr((ROOT / name).read_text()) + ', ' + variable + '.__dict__)\n'
    text += '_expected = json.loads(' + repr(plan_text) + ')\n'
    return text + (ROOT / 'build_container_probe.py').read_text()


def validate(value, expected, worker, installer, install_host, dependency_host, dependency):
    if (type(value) is not dict or value.get('schema') != worker.SCHEMA
            or value.get('status') != worker.SUCCESS or value.get('stage') != 'finished'
            or value.get('condition') != {'ruby': worker.VERSION, 'prefix': worker.PREFIX,
                'documentation': True, 'rust': False, 'make_jobs': 1}
            or value.get('configure_argv') != list(worker.CONFIGURE)
            or any(value.get(k) is not False for k in ('p1_04_complete', 'phase1_complete',
                   'role_verified', 'idempotence_verified', 'full_workspace_retained'))
            or any(value.get(k) is not True for k in ('ruby_build_verified', 'unknown_option_rejected',
                   'rust_absent_after_dependencies', 'public_commands_unchanged',
                   'rpm_and_repo_state_unchanged_by_build', 'ci_container_cleanup_required'))
            or not install_host.number(value.get('elapsed_seconds'), 2310)):
        raise Stop('BUILD_WORKER_SCHEMA')
    install_host.validate(value['dependencies'], expected, installer, dependency_host, dependency)
    worker.validate_runtime(value['runtime'])
    src = value['source']
    if (src.get('version') != worker.VERSION or src.get('sha256') != worker.SOURCE_SHA
            or src.get('sha256_expected') != worker.SOURCE_SHA or src.get('checksum_match') is not True
            or src.get('http_status') != 200 or src.get('extraction_verified') is not True
            or src.get('archive', {}).get('status') != 'PASSED'
            or src.get('archive', {}).get('gzip_eof_verified') is not True
            or src.get('redirect_policy') != 'no_redirect_followed'
            or type(src.get('bytes')) is not int or not 0 < src['bytes'] <= 64 * 1024 ** 2):
        raise Stop('BUILD_SOURCE_SCHEMA')
    if (value['public_before'] != value['public_after'] or
            len(value['public_before']) != 18 or
            value['commands'] != [{'name': n, 'path': worker.PREFIX + '/bin/' + n, 'returncode': 0}
                                  for n in worker.COMMANDS]):
        raise Stop('BUILD_COMMAND_SCHEMA')
    settings = value['build_settings']
    if (settings.get('USE_YJIT') != 0 or settings.get('USE_ZJIT') != 0
            or settings.get('configure_summary_jit_disabled') is not True
            or settings.get('makefile_values') != {'prefix': worker.PREFIX, 'ENABLE_SHARED': 'yes',
                'YJIT_SUPPORT': 'no', 'ZJIT_SUPPORT': 'no', 'DOCTARGETS': 'rdoc nodoc',
                'INSTALLDOC': 'all', 'EXTOUT': '.ext'}):
        raise Stop('BUILD_SETTING_SCHEMA')
    docs = value['documentation']
    if (type(docs) is not dict or any(docs.get(k) is not True for k in
            ('enabled', 'standard_String_verified', 'other_stores_disabled', 'installed_help_verified'))
            or docs != {'enabled': True, 'system_dir': worker.PREFIX + '/share/ri/4.0.0/system',
                'standard_String_verified': True, 'other_stores_disabled': True,
                'formatter': 'rdoc', 'installed_help_verified': True}):
        raise Stop('BUILD_DOCUMENTATION_SCHEMA')
    names = ['configure-negative', 'configure', 'make', 'install', 'runtime']
    names += ['command-' + n for n in worker.COMMANDS] + ['ri-help', 'ri-String']
    runs = value.get('runs')
    if type(runs) is not list or [r.get('name') for r in runs] != names:
        raise Stop('BUILD_RUNS_SCHEMA')
    for row in runs:
        if (type(row.get('returncode')) is not int or
                (row['returncode'] == 0) != (row['name'] != 'configure-negative')
                or not install_host.number(row.get('elapsed_seconds'), 2310)
                or type(row.get('bytes')) is not int or not 0 <= row['bytes'] <= worker.MAX_LOG
                or not install_host.valid_digest(row.get('sha256')) or type(row.get('tail')) is not str
                or len(row['tail'].encode()) > worker.TAIL_BYTES * 3):
            raise Stop('BUILD_RUN_SCHEMA')
    if (type(value.get('resources')) is not dict or value['resources'].get('sample_count', 0) <= 0
            or value.get('prefix_size', {}).get('allocated_bytes', 0) <= 0):
        raise Stop('BUILD_RESOURCE_SCHEMA')


def partial_measurements(value):
    """Allowlist bounded observations, never worker paths, extra keys or pass flags."""
    result = {'complete': False}
    elapsed = value.get('elapsed_seconds')
    if type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 2520:
        result['elapsed_seconds'] = elapsed
    resources = value.get('resources')
    if type(resources) is dict:
        kept = {}
        for key in ('sample_count', 'sample_interval_seconds',
                    'workspace_peak_allocated_bytes_sampled', 'prefix_peak_allocated_bytes_sampled',
                    'combined_peak_allocated_bytes_sampled', 'minimum_free_bytes_sampled',
                    'memory_peak_bytes'):
            item = resources.get(key)
            if type(item) is int and 0 <= item <= 2 ** 63 - 1:
                kept[key] = item
            elif key == 'memory_peak_bytes' and key in resources and item is None:
                kept[key] = None
        origin = resources.get('memory_peak_source')
        if type(origin) is str and origin in ('unavailable', '/sys/fs/cgroup/memory.peak',
                                             '/sys/fs/cgroup/memory/memory.max_usage_in_bytes'):
            kept['memory_peak_source'] = origin
        if kept:
            result['resources'] = kept
    size = value.get('prefix_size')
    if type(size) is dict:
        kept = {key: size[key] for key in ('apparent_bytes', 'allocated_bytes')
                if type(size.get(key)) is int and 0 <= size[key] <= 2 ** 63 - 1}
        if kept:
            result['prefix_size'] = kept
    if value.get('measurement_snapshot_error') == 'FINAL_RESOURCE_SNAPSHOT_FAILED':
        result['measurement_snapshot_error'] = 'FINAL_RESOURCE_SNAPSHOT_FAILED'
    return result


def diagnostics(value):
    """Bounded, credential-free container logs; never dump host environment or exceptions."""
    if type(value) is not dict or value.get('schema') != 'ruby-p1-build-container-r31':
        return {'reason': 'UNREADABLE_WORKER_RESULT'}
    result = {}
    for key in ('stage', 'reason', 'error_type'):
        item = value.get(key)
        if type(item) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,100}', item):
            result[key] = item
    if type(value.get('runs')) is list and len(value['runs']) <= 16:
        result['runs'] = []
        for row in value['runs']:
            if (type(row) is dict and type(row.get('name')) is str
                    and re.fullmatch(r'[a-zA-Z0-9-]{1,32}', row['name'])
                    and type(row.get('tail', '')) is str and len(row.get('tail', '').encode()) <= 49152):
                result['runs'].append({k: row[k] for k in
                    ('name', 'returncode', 'elapsed_seconds', 'bytes', 'sha256', 'tail') if k in row})
    result['partial_measurements'] = partial_measurements(value)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    for flag in ('allow-pull', 'allow-install', 'allow-ci416-replacements',
                 'allow-ruby-409-docs-on-build', 'ephemeral-ci'):
        parser.add_argument('--' + flag, action='store_true')
    args = parser.parse_args(argv)
    if (not all((args.allow_pull, args.allow_install, args.allow_ci416_replacements,
                 args.allow_ruby_409_docs_on_build, args.ephemeral_ci))
            or os.environ.get('CIRCLECI') != 'true' or os.environ.get('CIRCLE_BRANCH') != BRANCH
            or platform.system() != 'Linux' or platform.machine() != 'x86_64'):
        print('STOP: EXPLICIT_EPHEMERAL_RUBY_BUILD_APPROVAL_REQUIRED')
        return 3
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        print('STOP: OUTPUT_UNAVAILABLE_OR_EXISTS')
        return 3
    report = {'schema': 'ruby-p1-build-run-r31', 'status': 'INCOMPLETE', 'stage': 'preflight',
              'p1_04_complete': False, 'phase1_complete': False, 'cleanup_confirmed': None}
    possible, runtime = False, None
    run_id = uuid.uuid4().hex
    name = 'ruby-p1-' + run_id + '-build-r31'
    handlers = {}
    try:
        def interrupted(_sig, _frame):
            raise Stop('INTERRUPTED')
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.signal(sig, interrupted)
        runtime, inventory = load('runtime_smoke'), load('env_probe')
        worker, installer = load('build_container_probe'), load('install_container_probe')
        install_host, dependency_host = load('install_probe'), load('dependency_probe')
        dependency = load('dependency_container_probe')
        load('source_container_probe')
        plan_text = (ROOT / 'ci416_dependency_plan.json').read_text()
        if hashlib.sha256(plan_text.encode()).hexdigest() != installer.PLAN_SHA:
            raise Stop('BASELINE_PLAN_CHANGED')
        expected = json.loads(plan_text)
        socket = os.stat('/var/run/docker.sock')
        if not stat.S_ISSOCK(socket.st_mode) or socket.st_uid != 0:
            raise Stop('LOCAL_ROOT_DOCKER_SOCKET_REQUIRED')
        report['started_at'] = inventory.now()
        report['source_sha256'] = dict(HELPERS, **{'build_probe.py': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                      'ci416_dependency_plan.json': installer.PLAN_SHA})
        end = time.monotonic() + 2520
        report['stage'] = 'target_pull'
        runtime.command(runtime.DOCKER + ['pull', '--quiet', '--platform', 'linux/amd64', runtime.TARGET], end, 180)
        info = runtime.inspect_image(runtime.TARGET, runtime.TARGET_CONFIG, end)
        identity = inventory.registry_identity(runtime.TARGET, info, end)
        if (identity['platform_manifest_digest'] != runtime.TARGET_MANIFEST
                or identity['config_digest'] != runtime.TARGET_CONFIG):
            raise Stop('REGISTRY_MISMATCH')
        report['image'] = identity
        payload = bundle(plan_text)
        report['stage'] = 'build'
        possible = True
        process = subprocess.run(arguments(runtime, name, run_id), input=payload, text=True,
            capture_output=True, timeout=min(2310, max(1, end - time.monotonic())), check=False)
        report['command'] = {'returncode': process.returncode, 'stdout_bytes': len(process.stdout.encode()),
                             'stderr_bytes': len(process.stderr.encode())}
        if len(process.stdout.encode()) > 1048576:
            raise Stop('WORKER_OUTPUT_LIMIT')
        value = json.loads(process.stdout)
        report['failure'] = diagnostics(value)
        if type(value) is dict and type(value.get('dependencies')) is dict:
            report['failure']['dependency_failure'] = install_host.failure(value['dependencies'], installer)
        if process.stderr or process.returncode or type(value) is not dict or value.get('status') != worker.SUCCESS:
            raise Stop('RUBY_BUILD_INCOMPLETE')
        validate(value, expected, worker, installer, install_host, dependency_host, dependency)
        report.pop('failure')
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
    return 0 if report['status'] == 'RUBY_409_DOCS_ON_BUILD_VERIFIED' else 3


if __name__ == '__main__':
    raise SystemExit(main())
