#!/usr/bin/env python3
"""Explicitly gated, one-shot Ansible runtime proposal for an ephemeral CI VM."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent
BRANCH = 'plan/ruby-100-p1-env-r1'
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
CONTROLLER = 'ghcr.io/docker-images-mamono210/circleci-executors/molecule-docker@sha256:a80f2c478e9e183cdd782f8cdff79d1025cdc5291190e360898738fd8e6f7f41'
CONTROLLER_CONFIG = 'sha256:d406bc5afa3a8e24a8893f9e76766cf9648db1b1373ed9e6fcf82a1fadabea83'
TARGET = 'ghcr.io/docker-images-mamono210/ansible-test/centos-stream9@sha256:96fbd1eac7c972466192da5183e80deeacd226332265d1698b2581bf7666ccd2'
TARGET_CONFIG = 'sha256:6d26178c338fea1189cbb8fdf8db8a26dc4d315ce70d9926ebf38a476b13b319'
TARGET_MANIFEST = 'sha256:04f9e631a4f0ba1cbf9b13c4b29d6e9f1b0f5365f661c5128c220d66d5870e92'
ENV_SHA = '7773d3dfd2a9b4d9f77d1f45ad37c6ce2810752dafaebf57780fdd2089ef80b9'
FILES = ('runtime_controller.py', 'runtime_target.py', 'runtime_callback.py',
         'runtime_protocol.py', 'runtime_smoke.yml')


class Stop(Exception):
    pass


def load(name):
    spec = importlib.util.spec_from_file_location('runtime_' + name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def command(argv, deadline, timeout=30, allow_nonzero=False):
    timeout = min(timeout, deadline - time.monotonic())
    if timeout <= 0:
        raise Stop('TIME_LIMIT')
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise Stop('COMMAND_TIMEOUT') from None
    except OSError:
        raise Stop('COMMAND_UNAVAILABLE') from None
    if p.returncode and not allow_nonzero:
        raise Stop('COMMAND_EXIT_' + str(p.returncode))
    if p.stderr:
        raise Stop('UNCLASSIFIED_STDERR')
    if len(p.stdout.encode()) > 1024 * 1024:
        raise Stop('OUTPUT_TOO_LARGE')
    return (p.returncode, p.stdout) if allow_nonzero else p.stdout


def inspect_image(ref, config, deadline):
    fmt = ('{"id":{{json .Id}},"repo_digests":{{json .RepoDigests}},'
           '"os":{{json .Os}},"arch":{{json .Architecture}},'
           '"volumes":{{json .Config.Volumes}},"user":{{json .Config.User}}}')
    value = json.loads(command(DOCKER + ['image', 'inspect', '--format', fmt, ref], deadline))
    if (set(value) != {'id', 'repo_digests', 'os', 'arch', 'volumes', 'user'}
            or value['id'] != config or value['os'] != 'linux' or value['arch'] != 'amd64'
            or not isinstance(value['repo_digests'], list) or ref not in value['repo_digests']
            or any(not isinstance(x, str) for x in value['repo_digests'])):
        raise Stop('IMAGE_IDENTITY_MISMATCH')
    volumes = value.pop('volumes')
    if volumes is not None and (not isinstance(volumes, dict) or volumes):
        raise Stop('IMAGE_VOLUME_DECLARATION_OR_INVALID')
    if value['user'] not in (('circleci',) if ref == CONTROLLER else ('', 'root', '0')):
        raise Stop('IMAGE_USER_MISMATCH')
    value['volume_count'] = 0
    return value


def target_args(name, run_id):
    return DOCKER + ['run', '-d', '--pull=never', '--platform', 'linux/amd64',
                     '--name', name, '--label', 'ruby-p1.run=' + run_id,
                     '--network', 'none', '--no-healthcheck', '--pids-limit', '128',
                     '--memory', '768m', '--cpus', '1',
                     '--env', 'RUBY_P1_TARGET_FIXTURE=1', '--env', 'PYTHONDONTWRITEBYTECODE=1',
                     '--entrypoint', '/usr/bin/python3', TARGET_CONFIG,
                     '-I', '-B', '-c', 'import time; time.sleep(600)']


def controller_args(name, target, run_id, directory, socket_gid):
    return DOCKER + ['run', '--rm', '--pull=never', '--platform', 'linux/amd64',
                     '--name', name, '--label', 'ruby-p1.run=' + run_id,
                     '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                     '--security-opt', 'no-new-privileges', '--no-healthcheck',
                     '--pids-limit', '128', '--memory', '1g', '--cpus', '1',
                     '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=128m',
                     '--group-add', str(socket_gid),
                     '--mount', 'type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock,readonly',
                     '--mount', 'type=bind,src=' + str(directory) + ',dst=/p1,readonly',
                     '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'NO_COLOR=1',
                     '--entrypoint', 'python3', CONTROLLER_CONFIG,
                     '-B', '/p1/runtime_controller.py', target]


def cleanup(name, run_id):
    query = DOCKER + ['ps', '-aq', '--filter', 'name=^/' + name + '$',
                      '--filter', 'label=ruby-p1.run=' + run_id]
    try:
        end = time.monotonic() + 45
        ids = command(query, end).split()
        if not all(re.fullmatch(r'[0-9a-f]{12,64}', value) for value in ids):
            return False
        if ids:
            command(DOCKER + ['rm', '-f'] + ids, end)
        return not command(query, end).strip()
    except Exception:
        return False


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    for name in ('allow-pull', 'ephemeral-ci', 'allow-ci-docker-api', 'allow-disposable-sudo-fixture'):
        parser.add_argument('--' + name, action='store_true')
    args = parser.parse_args(argv)
    # No Docker mutation before all explicit gates and local VM checks.
    if (not all((args.allow_pull, args.ephemeral_ci, args.allow_ci_docker_api,
                 args.allow_disposable_sudo_fixture))
            or os.environ.get('CIRCLECI') != 'true' or os.environ.get('CIRCLE_BRANCH') != BRANCH
            or platform.system() != 'Linux' or platform.machine() != 'x86_64'):
        print('STOP: EXPLICIT_EPHEMERAL_CI_AND_BOUNDARIES_REQUIRED')
        return 3
    report = {'schema': 'ruby-p1-runtime-run-r11', 'status': 'INCOMPLETE', 'stage': 'preflight',
              'p1_02_complete': False, 'phase1_complete': False,
              'production_become_verified': False, 'production_mounts_verified': False,
              'repository_access_verified': False, 'dependency_resolution_verified': False,
              'stock_sudo_nonroot_verified': False, 'fixture_become_verified': False,
              'cleanup': {}, 'scope': 'disposable_ci_containers_only'}
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        print('STOP: OUTPUT_UNAVAILABLE_OR_EXISTS')
        return 3
    run_id = uuid.uuid4().hex
    target = 'ruby-p1-' + run_id + '-runtime-target'
    controller = 'ruby-p1-' + run_id + '-runtime-controller'
    possible = []
    handlers = {}

    def interrupted(_signum, _frame):
        raise Stop('INTERRUPTED')

    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.signal(sig, interrupted)
        sock = os.stat('/var/run/docker.sock')
        if not stat.S_ISSOCK(sock.st_mode) or sock.st_uid != 0:
            raise Stop('LOCAL_ROOT_DOCKER_SOCKET_REQUIRED')
        if hashlib.sha256((ROOT / 'env_probe.py').read_bytes()).hexdigest() != ENV_SHA:
            raise Stop('HELPER_CHANGED')
        inventory = load('env_probe')
        protocol = load('runtime_protocol')
        end = time.monotonic() + 600
        report['started_at'] = inventory.now()
        report['source_sha256'] = {n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest()
                                   for n in FILES + ('runtime_smoke.py', 'env_probe.py')}
        report['images'] = {}
        for kind, ref, config in (('controller', CONTROLLER, CONTROLLER_CONFIG),
                                  ('target', TARGET, TARGET_CONFIG)):
            report['stage'] = kind + '_pull'
            print(report['stage'], flush=True)
            command(DOCKER + ['pull', '--quiet', '--platform', 'linux/amd64', ref], end, 240)
            report['stage'] = kind + '_identity'
            info = inspect_image(ref, config, end)
            registry = inventory.registry_identity(ref, info, end)
            expected_manifest = ref.split('@')[1] if kind == 'controller' else TARGET_MANIFEST
            if registry['platform_manifest_digest'] != expected_manifest or registry['config_digest'] != config:
                raise Stop('REGISTRY_MISMATCH')
            report['images'][kind] = registry
        report['stage'] = 'target_start'
        possible.append(target)
        command(target_args(target, run_id), end)
        with tempfile.TemporaryDirectory(prefix='ruby-p1-r11-') as directory:
            directory = Path(directory)
            directory.chmod(0o755)
            (directory / 'callback_plugins').mkdir(mode=0o755)
            for name in FILES:
                destination = directory / ('callback_plugins' if name == 'runtime_callback.py' else '') / name
                shutil.copyfile(ROOT / name, destination)
                destination.chmod(0o444)
            report['stage'] = 'controller_runtime'
            possible.append(controller)
            controller_rc, output = command(controller_args(controller, target, run_id, directory, sock.st_gid), end, 240, allow_nonzero=True)
            value = json.loads(output)
            if value.get('status') == 'INCOMPLETE':
                # Only fixed labels and numeric counts, never arbitrary error text.
                attempt = {'status': 'INCOMPLETE'}
                if value.get('stage') in ('preflight', 'ansible_playbook'):
                    attempt['stage'] = value['stage']
                counts = value.get('command', {})
                if (set(counts) == {'returncode', 'stdout_bytes', 'stderr_bytes'}
                        and all(type(x) is int for x in counts.values())):
                    attempt['command'] = counts
                report['runtime_attempt'] = attempt
                raise Stop('CONTROLLER_RUNTIME_UNCONFIRMED')
            if controller_rc != 0:
                raise Stop('CONTROLLER_EXIT_STATUS_MISMATCH')
            protocol.validate_report(value)
            report['runtime'] = value
            report['fixture_become_verified'] = True
            report['status'] = 'ANSIBLE_RUNTIME_AND_FIXTURE_BECOME_PASSED'
            report['stage'] = 'finished'
    except Stop as error:
        report['reason'] = str(error)
    except Exception:
        report['reason'] = 'UNEXPECTED_OR_SCHEMA_ERROR'
    finally:
        for name in reversed(possible):
            report['cleanup']['controller' if name == controller else 'target'] = cleanup(name, run_id)
        report['cleanup_confirmed'] = (all(report['cleanup'].values()) if possible else None)
        if possible and report['cleanup_confirmed'] is not True:
            report.update(status='INCOMPLETE', reason='CLEANUP_UNCONFIRMED')
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        with os.fdopen(fd, 'w') as f:
            json.dump(report, f, sort_keys=True, indent=2)
            f.write('\n')
    print(report['status'], flush=True)
    return 0 if report['status'] == 'ANSIBLE_RUNTIME_AND_FIXTURE_BECOME_PASSED' else 3


if __name__ == '__main__':
    sys.exit(main())
