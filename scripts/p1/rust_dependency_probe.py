#!/usr/bin/env python3
"""r33: measure the Ruby dependencies plus Rust, without installing any RPM."""
import argparse
import hashlib
import importlib.util
import json
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
SCHEMA = 'ruby-p1-rust-dependency-container-r33'
SUCCESS = 'RUST_DEPENDENCY_SOLVER_MEASURED'
PACKAGES = ('gcc', 'make', 'tar', 'gzip', 'ca-certificates', 'openssl-devel',
            'libyaml-devel', 'zlib-devel', 'libffi-devel', 'rust')
HELPERS = {
    'runtime_smoke.py': '450a33babab510d9d529e309cbfd0ea1a9d76ef4728f1e6190a6a0f41935ecc5',
    'env_probe.py': '7773d3dfd2a9b4d9f77d1f45ad37c6ce2810752dafaebf57780fdd2089ef80b9',
    'dependency_probe.py': '240c2304eb28c8d769cb6d5cfaf2ae964175e50339d9debf358e7331a8807018',
    'dependency_container_probe.py': '2118deac29ca85c050e4cee8291b3a062f7d9646fe0c69739562794922904b1d',
    'ci416_dependency_plan.json': 'dab9f189074751b8555cd8dd9edec219d6d8b1e0e275d3b569772f28fa332f27',
}


class Stop(Exception):
    pass


def verified_text(name):
    data = (ROOT / name).read_bytes()
    if name not in HELPERS or hashlib.sha256(data).hexdigest() != HELPERS[name]:
        raise Stop('HELPER_CHANGED')
    return data.decode('utf-8')


def load(name):
    verified_text(name + '.py')
    spec = importlib.util.spec_from_file_location('r33_' + name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def profile(worker):
    if (worker.PACKAGES != PACKAGES[:-1] or worker.SCHEMA != 'ruby-p1-dependency-container-r26'
            or worker.SUCCESS != 'DEPENDENCY_SOLVER_MEASURED'):
        raise Stop('DEPENDENCY_PROFILE_CHANGED')
    worker.PACKAGES, worker.SCHEMA, worker.SUCCESS = PACKAGES, SCHEMA, SUCCESS
    return worker


def bundle():
    # Isolated module state; the existing dependency source and Role stay unchanged.
    text = 'import types\n_worker = types.ModuleType("r33_dependency")\n'
    text += 'exec(' + repr(verified_text('dependency_container_probe.py')) + ', _worker.__dict__)\n'
    text += '_worker.PACKAGES = ' + repr(PACKAGES) + '\n'
    text += '_worker.SCHEMA = ' + repr(SCHEMA) + '\n'
    text += '_worker.SUCCESS = ' + repr(SUCCESS) + '\n'
    return text + 'raise SystemExit(_worker.main())\n'


def validate(value, host, worker, expected):
    host.validate(value, worker)
    if (value['rpm_before_after'] != expected['baseline_rpm']
            or value['configuration_before_after'] != expected['baseline_configuration']):
        raise Stop('BASELINE_CHANGED')
    for item in value['conditions']:
        for field in ('install_set', 'remove_set'):
            keys = [json.dumps(row, sort_keys=True) for row in item[field]]
            if len(keys) != len(set(keys)):
                raise Stop('DUPLICATE_PLAN_ENTRY')
        rust = item['candidates'][-1]
        if rust['installed']:
            raise Stop('RUST_ALREADY_INSTALLED')
        if item['resolution'] == 'RESOLVED':
            selected = [r for r in item['install_set'] if r['name'] == 'rust']
            if (len(selected) != 1 or selected[0]['arch'] != 'x86_64'
                    or selected[0] not in rust['available']):
                raise Stop('RUST_PLAN_MISMATCH')


def comparison(value, expected):
    current = value['conditions'][1]
    result = {'reference': 'CI416', 'rust_package':
              [r for r in current['install_set'] if r['name'] == 'rust'],
              'planned_replacements': current['planned_replacements'],
              'changes_may_include_repository_drift': True}
    for field in ('install_set', 'remove_set'):
        old = {json.dumps(row, sort_keys=True): row for row in expected[field]}
        new = {json.dumps(row, sort_keys=True): row for row in current[field]}
        result[field] = {'new_entries': [new[k] for k in sorted(new.keys() - old.keys())],
                         'no_longer_planned': [old[k] for k in sorted(old.keys() - new.keys())],
                         'unchanged_count': len(old.keys() & new.keys())}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    for name in ('allow-pull', 'allow-repo-metadata', 'allow-rust-solver', 'ephemeral-ci'):
        parser.add_argument('--' + name, action='store_true')
    args = parser.parse_args(argv)
    if (not all((args.allow_pull, args.allow_repo_metadata, args.allow_rust_solver, args.ephemeral_ci))
            or os.environ.get('CIRCLECI') != 'true' or os.environ.get('CIRCLE_BRANCH') != BRANCH
            or platform.system() != 'Linux' or platform.machine() != 'x86_64'):
        print('STOP: EXPLICIT_EPHEMERAL_RUST_SOLVER_APPROVAL_REQUIRED')
        return 3
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        print('STOP: OUTPUT_UNAVAILABLE_OR_EXISTS')
        return 3
    report = {'schema': 'ruby-p1-rust-dependency-run-r33', 'status': 'INCOMPLETE',
              'stage': 'preflight', 'p1_04_complete': False, 'phase1_complete': False,
              'rust_installed': False, 'ruby_build_verified': False, 'cleanup_confirmed': None}
    runtime, possible, handlers = None, False, {}
    run_id = uuid.uuid4().hex
    name = 'ruby-p1-' + run_id + '-rust-dependency-r33'
    try:
        def interrupted(_signum, _frame):
            raise Stop('INTERRUPTED')
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.signal(sig, interrupted)
        runtime, inventory = load('runtime_smoke'), load('env_probe')
        host, worker = load('dependency_probe'), profile(load('dependency_container_probe'))
        expected = json.loads(verified_text('ci416_dependency_plan.json'))
        script = bundle()
        socket = os.stat('/var/run/docker.sock')
        if not stat.S_ISSOCK(socket.st_mode) or socket.st_uid != 0:
            raise Stop('LOCAL_ROOT_DOCKER_SOCKET_REQUIRED')
        report['started_at'] = inventory.now()
        report['source_sha256'] = {n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest()
                                  for n in (*HELPERS, 'rust_dependency_probe.py')}
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
        remaining = min(540, end - time.monotonic())
        if remaining <= 0:
            raise Stop('TIME_LIMIT')
        possible = True
        result = subprocess.run(host.arguments(runtime, name, run_id), input=script,
                                text=True, capture_output=True, timeout=remaining, check=False)
        report['command'] = {'returncode': result.returncode,
                             'stdout_bytes': len(result.stdout.encode()),
                             'stderr_bytes': len(result.stderr.encode())}
        if len(result.stdout.encode()) > 262144:
            raise Stop('WORKER_OUTPUT_REJECTED')
        if result.stderr:
            report['failure_diagnostic'] = host.failure_summary(result.stdout, worker)
            raise Stop('WORKER_OUTPUT_REJECTED')
        value = json.loads(result.stdout)
        if type(value) is not dict:
            raise Stop('WORKER_SCHEMA')
        if value.get('status') != worker.SUCCESS:
            report['failure_diagnostic'] = host.failure_summary(result.stdout, worker)
            raise Stop('DEPENDENCY_MEASUREMENT_INCOMPLETE')
        validate(value, host, worker, expected)
        if result.returncode != 0:
            raise Stop('WORKER_EXIT_MISMATCH')
        report['measurement'] = value
        if value['crb_on_resolved'] is not True:
            raise Stop('CRB_ON_NOT_RESOLVED')
        report['comparison_to_ci416'] = comparison(value, expected)
        report.update(status=SUCCESS, stage='finished')
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
    return 0 if report['status'] == SUCCESS else 3


if __name__ == '__main__':
    raise SystemExit(main())
