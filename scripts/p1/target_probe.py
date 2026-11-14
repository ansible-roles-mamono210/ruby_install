#!/usr/bin/env python3
"""One fixed-image, offline target probe on an explicitly approved ephemeral CI VM."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parent
ENV_SHA256 = '7773d3dfd2a9b4d9f77d1f45ad37c6ce2810752dafaebf57780fdd2089ef80b9'
TARGET = 'ghcr.io/docker-images-mamono210/ansible-test/centos-stream9@sha256:96fbd1eac7c972466192da5183e80deeacd226332265d1698b2581bf7666ccd2'
MANIFEST = 'sha256:04f9e631a4f0ba1cbf9b13c4b29d6e9f1b0f5365f661c5128c220d66d5870e92'
CONFIG = 'sha256:6d26178c338fea1189cbb8fdf8db8a26dc4d315ce70d9926ebf38a476b13b319'
BRANCH = 'plan/ruby-100-p1-env-r1'
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
SUCCESS = 'TARGET_OFFLINE_IMPORT_CONFIG_PASSED'


class Stop(Exception):
    pass


def command(args, timeout=30, source=None, deadline=None, diagnostic_label=None):
    if diagnostic_label not in (None, 'IMAGE_INSPECT'):
        raise Stop('INVALID_DIAGNOSTIC_LABEL')

    def stop(code):
        raise Stop((diagnostic_label + '_' if diagnostic_label else '') + code)

    if deadline is not None:
        timeout = min(timeout, deadline - time.monotonic())
    if timeout <= 0:
        stop('TIME_LIMIT')
    try:
        result = subprocess.run(args, input=source, text=True, capture_output=True,
                                timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        stop('COMMAND_TIMEOUT')
    except OSError:
        stop('COMMAND_UNAVAILABLE')
    if result.returncode:
        if diagnostic_label:
            # Persist a fixed category only; never return raw stderr or arguments.
            category = ('TEMPLATE_ERROR' if result.stderr.lstrip().lower().startswith('template parsing error:')
                        else 'OTHER_STDERR' if result.stderr else 'NO_STDERR')
            stop(category + '_EXIT_' + str(result.returncode))
        stop('COMMAND_EXIT_' + str(result.returncode))
    if result.stderr:
        stop('UNCLASSIFIED_STDERR')
    if len(result.stdout.encode('utf-8')) > 1024 * 1024:
        stop('OUTPUT_TOO_LARGE')
    return result.stdout


def load_inventory():
    path = ROOT / 'env_probe.py'
    if hashlib.sha256(path.read_bytes()).hexdigest() != ENV_SHA256:
        raise Stop('INVENTORY_HELPER_CHANGED')
    spec = importlib.util.spec_from_file_location('r9_existing_inventory', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect_image(deadline):
    # Do not request Env, labels, command/entrypoint text, or healthcheck text.
    fmt = ('{"id":{{json .Id}},"repo_digests":{{json .RepoDigests}},'
           '"os":{{json .Os}},"arch":{{json .Architecture}},'
           '"volumes":{{json .Config.Volumes}}}')
    raw = command(DOCKER + ['image', 'inspect', '--format', fmt, TARGET],
                  deadline=deadline, diagnostic_label='IMAGE_INSPECT')
    try:
        info = json.loads(raw)
    except (ValueError, TypeError):
        raise Stop('IMAGE_INSPECT_INVALID_JSON') from None
    if (not isinstance(info, dict)
            or set(info) != {'id', 'repo_digests', 'os', 'arch', 'volumes'}):
        raise Stop('IMAGE_INSPECT_INVALID_FIELDS')
    # Volume paths exist only in this local response. Return only their count.
    volumes = info.pop('volumes')
    if volumes is not None and not isinstance(volumes, dict):
        raise Stop('IMAGE_INSPECT_INVALID_VOLUMES')
    info['volume_count'] = 0 if volumes is None else len(volumes)
    if info.get('id') != CONFIG or info.get('os') != 'linux' or info.get('arch') != 'amd64':
        raise Stop('IMAGE_IDENTITY_MISMATCH')
    if info['volume_count'] != 0:
        raise Stop('IMAGE_VOLUME_DECLARATION')
    if (not isinstance(info['repo_digests'], list) or not info['repo_digests']
            or not all(isinstance(value, str) for value in info['repo_digests'])):
        raise Stop('IMAGE_INSPECT_INVALID_REPO_DIGESTS')
    return info


def run_arguments(name, run_id):
    return DOCKER + [
        'run', '--rm', '--pull=never', '--platform', 'linux/amd64',
        '--name', name, '--label', 'ruby-p1.run=' + run_id,
        '--network', 'none', '--read-only', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--no-healthcheck',
        '--pids-limit', '128', '--memory', '512m', '--cpus', '1',
        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m',
        '--env', 'PYTHONDONTWRITEBYTECODE=1',
        '--entrypoint', 'python3', '-i', CONFIG, '-I', '-B', '-',
    ]


def cleanup(name, run_id):
    query = DOCKER + ['ps', '-aq', '--filter', 'name=^/' + name + '$',
                      '--filter', 'label=ruby-p1.run=' + run_id]
    try:
        ids = command(query, timeout=10).split()
        if not all(re.fullmatch(r'[0-9a-f]{12,64}', value) for value in ids):
            return False
        if ids:
            command(DOCKER + ['rm', '-f'] + ids, timeout=20)
        return not command(query, timeout=10).strip()
    except Stop:
        return False


def assess(probe):
    if not isinstance(probe, dict) or probe.get('schema') != 'ruby-p1-target-offline-r9':
        raise Stop('PROBE_SCHEMA_MISMATCH')
    if probe.get('scope') != 'restricted_probe_container' or probe.get('status') != 'COLLECTED' or probe.get('errors') != []:
        raise Stop('PROBE_INCOMPLETE')
    facts = probe.get('platform', {})
    osr = facts.get('os', {})
    if (facts.get('arch') != 'x86_64' or facts.get('python') != '3.9.19'
            or osr.get('ID') != 'centos' or osr.get('VERSION_ID') != '9'
            or 'CentOS Stream 9' not in osr.get('PRETTY_NAME', '')):
        raise Stop('TARGET_BASELINE_MISMATCH')
    dnf = probe.get('dnf', {})
    if (dnf.get('status') != 'IMPORT_AND_CONFIG_ONLY' or dnf.get('cacheonly_override') is not True
            or dnf.get('plugins_initialized') is not False or dnf.get('metadata_loaded') is not False):
        raise Stop('DNF_SCOPE_MISMATCH')
    repos = dnf.get('repositories', [])
    if not repos or len({row['id'] for row in repos}) != len(repos):
        raise Stop('REPOSITORY_CONFIG_INCOMPLETE')
    crb = [row for row in repos if row['id'] == 'crb']
    if len(crb) != 1 or crb[0].get('enabled') is not False:
        raise Stop('CRB_BASELINE_MISMATCH')
    if not all(probe.get('tools_present', {}).get(name) is True for name in ('python3', 'dnf', 'rpm')):
        raise Stop('REQUIRED_TARGET_TOOL_MISSING')
    mounts = probe.get('mounts', {})
    if (mounts.get('/', {}).get('ro') is not True
            or mounts.get('/tmp', {}).get('noexec') is not True
            or mounts.get('/tmp', {}).get('ro') is not False):
        raise Stop('PROBE_MOUNT_OVERRIDE_MISMATCH')


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--allow-pull', action='store_true')
    parser.add_argument('--ephemeral-ci', action='store_true')
    args = parser.parse_args(argv)
    report = {'schema': 'ruby-p1-target-run-r10', 'status': 'INCOMPLETE',
              'p1_02_complete': False, 'phase1_complete': False,
              'requested_ref': TARGET, 'stage': 'preflight',
              'scope': 'offline_import_and_configuration_only',
              'probe_overrides': {'network': 'none', 'rootfs': 'read-only',
                                  'tmp': 'tmpfs,rw,nosuid,nodev,noexec,64m',
                                  'capabilities': 'none', 'no_new_privileges': True,
                                  'healthcheck': 'disabled', 'dnf_cacheonly': True},
              'normal_target_mounts_verified': False, 'become_verified': False,
              'repository_access_verified': False, 'dependency_resolution_verified': False,
              'cleanup_confirmed': None}
    output = Path(args.output)
    try:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        print('STOP: OUTPUT_UNAVAILABLE_OR_EXISTS', flush=True)
        return 3
    name = run_id = None
    container_possible = False
    old_handlers = {}

    def interrupted(_signum, _frame):
        raise Stop('INTERRUPTED')

    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            old_handlers[sig] = signal.signal(sig, interrupted)
        if (not args.ephemeral_ci or not args.allow_pull or os.environ.get('CIRCLECI') != 'true'
                or os.environ.get('CIRCLE_BRANCH') != BRANCH):
            raise Stop('EXPLICIT_EPHEMERAL_CI_REQUIRED')
        if platform.system() != 'Linux' or platform.machine() != 'x86_64':
            raise Stop('HOST_PLATFORM_MISMATCH')
        sock = os.stat('/var/run/docker.sock')
        if not stat.S_ISSOCK(sock.st_mode) or sock.st_uid != 0:
            raise Stop('LOCAL_DOCKER_SOCKET_REQUIRED')
        inventory = load_inventory()
        run_id = uuid.uuid4().hex
        name = 'ruby-p1-' + run_id + '-target-r10'
        report.update(run_id=run_id, started_at=inventory.now())
        deadline = time.monotonic() + 600
        report['source_sha256'] = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (Path(__file__), ROOT / 'target_container_probe.py', ROOT / 'env_probe.py')}
        report['stage'] = 'pull'
        print('target: pull fixed digest', flush=True)
        command(DOCKER + ['pull', '--quiet', '--platform', 'linux/amd64', TARGET],
                timeout=240, deadline=deadline)
        report['stage'] = 'image_inspect'
        info = inspect_image(deadline)
        report['stage'] = 'registry_identity'
        registry = inventory.registry_identity(TARGET, info, deadline)
        if registry.get('platform_manifest_digest') != MANIFEST or registry.get('config_digest') != CONFIG:
            raise Stop('REGISTRY_BASELINE_MISMATCH')
        report['registry'] = registry
        report['image_volume_count'] = info['volume_count']
        report['stage'] = 'container_probe'
        print('target: offline imports and configuration', flush=True)
        container_possible = True
        value = json.loads(command(run_arguments(name, run_id), timeout=150,
                                   source=(ROOT / 'target_container_probe.py').read_text(), deadline=deadline))
        # Persist only the structured, fixed-schema output produced by this source.
        if not isinstance(value, dict) or value.get('schema') != 'ruby-p1-target-offline-r9':
            raise Stop('PROBE_SCHEMA_MISMATCH')
        report['probe'] = value
        assess(value)
        report['status'] = SUCCESS
        report['stage'] = 'finished'
    except Stop as error:
        report['reason'] = str(error)
    except Exception:
        # Includes errors from the pre-existing registry helper; never print details.
        report['reason'] = 'UNEXPECTED_OR_REGISTRY_ERROR'
    finally:
        if container_possible:
            report['cleanup_confirmed'] = cleanup(name, run_id)
            if not report['cleanup_confirmed']:
                report['status'] = 'INCOMPLETE'
                report['reason'] = 'CLEANUP_UNCONFIRMED'
        else:
            report['container_not_started'] = True
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
        with os.fdopen(fd, 'w') as handle:
            json.dump(report, handle, sort_keys=True, indent=2)
            handle.write('\n')
    print(report['status'], flush=True)
    return 0 if report['status'] == SUCCESS else 3


if __name__ == '__main__':
    sys.exit(main())
