#!/usr/bin/env python3
"""P1-02 inventory proposal. No installs, builds, Docker socket chmod, or Role run."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid

IMAGES = {
    'controller': 'ghcr.io/docker-images-mamono210/circleci-executors/molecule-docker:26.2.0-py3.14-ans13.4.0',
    'target': 'ghcr.io/docker-images-mamono210/ansible-test/centos-stream9:latest',
    'lint': 'ghcr.io/docker-images-mamono210/circleci-executors/ansible-lint:26.1.1-py3.14',
}
EXPECTED = {'ansible-core': '2.21.6', 'molecule': '26.11.0', 'molecule-plugins': '26.11.0'}
COLLECTIONS = {'community.general': '13.5.1', 'ansible.posix': '2.2.2', 'community.docker': '5.4.0'}
DIAGNOSTIC_IMAGES = {
    'controller': 'ghcr.io/docker-images-mamono210/circleci-executors/molecule-docker@sha256:b4a4089328cf6acb42e04725f774e68aaafb52991ee74ee9e36e8ae52226be8b',
    'lint': 'ghcr.io/docker-images-mamono210/circleci-executors/ansible-lint@sha256:4ea7fe7ebbe7fd06bd5a7fc61b8931c3303a11c9bd4eb06431a810f5914b8718',
}
CANDIDATE_CONTROLLER = 'ghcr.io/docker-images-mamono210/circleci-executors/molecule-docker@sha256:a80f2c478e9e183cdd782f8cdff79d1025cdc5291190e360898738fd8e6f7f41'
CANDIDATE_CONFIG_DIGEST = 'sha256:d406bc5afa3a8e24a8893f9e76766cf9648db1b1373ed9e6fcf82a1fadabea83'
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']


class Stop(Exception):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


def run(args, timeout=45, stdin=None, deadline=None):
    if deadline is not None:
        timeout = min(timeout, deadline - time.monotonic())
    if timeout <= 0:
        raise Stop('TOTAL_TIME_LIMIT')
    try:
        p = subprocess.run(args, input=stdin, capture_output=True, text=True,
                           timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise Stop('COMMAND_TIMEOUT') from None
    except OSError:
        raise Stop('COMMAND_UNAVAILABLE') from None
    # Raw stderr is deliberately not persisted: registry errors may carry credentials.
    if p.returncode:
        raise Stop('COMMAND_EXIT_' + str(p.returncode))
    if len(p.stdout) > 8 * 1024 * 1024:
        raise Stop('OUTPUT_TOO_LARGE')
    return p.stdout


def parsed(args, **kwargs):
    try:
        value = json.loads(run(args, **kwargs))
    except ValueError:
        raise Stop('INVALID_JSON') from None
    if not isinstance(value, dict):
        raise Stop('INVALID_JSON_OBJECT')
    return value


def host_inventory():
    release = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            if key in {'ID', 'VERSION_ID', 'PRETTY_NAME'}:
                words = shlex.split(value)
                release[key] = words[0] if words else ''
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        if key in {'MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree'}:
            memory[key + '_KiB'] = int(value.split()[0])
    disk = shutil.disk_usage(Path.cwd())
    return {'os': release, 'arch': platform.machine(), 'kernel': platform.release(),
            'cpu_count': os.cpu_count(), 'memory': memory,
            'working_filesystem_bytes': {'total': disk.total, 'free': disk.free},
            'collector_python': platform.python_version(),
            'cgroup_v2_present': Path('/sys/fs/cgroup/cgroup.controllers').exists()}


def registry_identity(image, info, deadline):
    repo = image.split('@', 1)[0] if '@' in image else image.rsplit(':', 1)[0]
    refs = [x for x in (info.get('repo_digests') or []) if x.startswith(repo + '@')]
    if len(refs) != 1 or not DIGEST.fullmatch(refs[0].split('@', 1)[1]):
        raise Stop('REGISTRY_DIGEST_NOT_UNIQUE')
    root_ref = refs[0]
    if '@' in image and root_ref != image:
        raise Stop('REQUESTED_DIGEST_MISMATCH')
    doc = parsed(DOCKER + ['buildx', 'imagetools', 'inspect', '--raw', root_ref], deadline=deadline)
    root_digest = root_ref.split('@', 1)[1]
    selected = root_digest
    index_digest = None
    if 'manifests' in doc:
        matches = [m for m in doc['manifests'] if m.get('platform', {}).get('os') == 'linux'
                   and m.get('platform', {}).get('architecture') == 'amd64'
                   and m.get('platform', {}).get('variant', '') in ('', None)]
        if len(matches) != 1 or not DIGEST.fullmatch(matches[0].get('digest', '')):
            raise Stop('AMD64_MANIFEST_NOT_UNIQUE')
        index_digest, selected = root_digest, matches[0]['digest']
        doc = parsed(DOCKER + ['buildx', 'imagetools', 'inspect', '--raw', repo + '@' + selected], deadline=deadline)
    if doc.get('config', {}).get('digest') != info['id']:
        raise Stop('MANIFEST_IMAGE_ID_MISMATCH')
    return {'registry_reference': root_ref, 'index_digest': index_digest,
            'platform_manifest_digest': selected, 'config_digest': info['id']}


def assess(kind, probe):
    mismatches, unknown = [], []
    if probe.get('arch') != 'x86_64':
        mismatches.append('architecture')
    if kind == 'controller':
        if not probe.get('python', '').startswith('3.14.'):
            mismatches.append('controller_python')
        for name, version in EXPECTED.items():
            if probe.get('packages', {}).get(name) != version:
                mismatches.append(name)
        if probe.get('collections_status') != 'COLLECTED':
            unknown.append('collections')
        else:
            for name, version in COLLECTIONS.items():
                matches = [x['version'] for x in probe.get('collections', []) if x['name'] == name]
                if not matches or set(matches) != {version}:
                    mismatches.append(name)
    elif kind == 'target':
        osr = probe.get('os', {})
        if (osr.get('ID') != 'centos' or osr.get('VERSION_ID') != '9'
                or 'CentOS Stream 9' not in osr.get('PRETTY_NAME', '')):
            mismatches.append('target_os')
        if not probe.get('python', '').startswith('3.9.'):
            mismatches.append('target_python')
        if not probe.get('dnf_python_module_found'):
            unknown.append('dnf_module')
        if probe.get('rpm_status') != 'COLLECTED':
            unknown.append('rpm_inventory')
        if probe.get('repo_status') != 'CONFIG_ONLY':
            unknown.append('repository_config')
    elif not probe.get('packages', {}).get('ansible-lint'):
        unknown.append('ansible_lint')
    return {'mismatches': mismatches, 'unconfirmed': unknown}


def cleanup(name, run_id):
    try:
        ids = run(DOCKER + ['ps', '-aq', '--filter', 'name=^/' + name + '$',
                           '--filter', 'label=ruby-p1.run=' + run_id], timeout=10).split()
        if not all(re.fullmatch(r'[0-9a-f]{12,64}', cid) for cid in ids):
            return False
        if ids:
            run(DOCKER + ['rm', '-f'] + ids, timeout=15)
        return True
    except Stop:
        return False


def collect_image(kind, image, allow_pull, run_id, deadline, source, galaxy_cache=None,
                  expected_image_id=None, controller_checks=False):
    row = {'requested_ref': image, 'started_at': now(), 'status': 'INCOMPLETE'}
    if galaxy_cache not in (None, 'tmp'):
        raise Stop('INVALID_GALAXY_CACHE_MODE')
    row['galaxy_cache_mode'] = 'original' if galaxy_cache is None else 'tmp'
    name = 'ruby-p1-' + run_id + '-' + kind
    created_possible = False
    try:
        if allow_pull:
            row['stage'] = 'pull'
            print(kind + ': pull', flush=True)
            run(DOCKER + ['pull', '--quiet', '--platform', 'linux/amd64', image], timeout=240, deadline=deadline)
        row['stage'] = 'local_image_inspect'
        fmt = ('{"id":{{json .Id}},"repo_digests":{{json .RepoDigests}},'
               '"os":{{json .Os}},"arch":{{json .Architecture}},"user":{{json .Config.User}}}')
        info = parsed(DOCKER + ['image', 'inspect', '--format', fmt, image], deadline=deadline)
        row['image'] = info
        if info['os'] != 'linux' or info['arch'] != 'amd64' or not DIGEST.fullmatch(info['id']):
            raise Stop('IMAGE_PLATFORM_MISMATCH')
        row['stage'] = 'registry_manifest'
        print(kind + ': manifest', flush=True)
        row['registry'] = registry_identity(image, info, deadline)
        if expected_image_id is not None and info['id'] != expected_image_id:
            raise Stop('CANDIDATE_CONFIG_DIGEST_MISMATCH')
        # Use the validated immutable local config digest; never resolve the tag again.
        args = DOCKER + ['run', '--rm', '--pull=never', '--platform', 'linux/amd64',
                        '--name', name, '--label', 'ruby-p1.run=' + run_id,
                        '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                        '--security-opt', 'no-new-privileges', '--pids-limit', '128',
                        '--memory', '512m', '--cpus', '1',
                        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m',
                        '--env', 'ANSIBLE_LOCAL_TEMP=/tmp/ansible-local',
                        '--env', 'ANSIBLE_NOCOLOR=1', '--env', 'XDG_CACHE_HOME=/tmp/cache']
        if galaxy_cache == 'tmp':
            args += ['--env', 'ANSIBLE_GALAXY_CACHE_DIR=/tmp/ansible-galaxy-cache']
        if controller_checks:
            args += ['--env', 'RUBY_P1_CONTROLLER_CHECKS=1',
                     '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'PIP_DISABLE_PIP_VERSION_CHECK=1',
                     '--env', 'NO_COLOR=1']
        args += ['--entrypoint', 'python3', '-i', info['id'], '-']
        created_possible = True
        row['stage'] = 'container_inventory'
        print(kind + ': inventory', flush=True)
        probe = parsed(args, stdin=source, timeout=150, deadline=deadline)
        row['probe'] = probe
        row['assessment'] = assess(kind, probe)
        row['status'] = 'COLLECTED'
        row['stage'] = 'finished'
    except Stop as exc:
        if str(exc) == 'INTERRUPTED':
            raise
        row['error_code'] = str(exc)
    except (KeyError, TypeError, ValueError, AttributeError):
        row['error_code'] = 'INVALID_PROBE_SCHEMA'
    finally:
        row['cleanup_confirmed'] = cleanup(name, run_id) if created_possible else True
        row['finished_at'] = now()
    return row


def diagnostic_summary(images):
    """A failed original command can be observed; timeout/missing data cannot pass."""
    comparisons = {}
    complete = True
    for kind in DIAGNOSTIC_IMAGES:
        pair = [images.get(kind + '_' + mode, {}) for mode in ('original', 'tmp')]
        observed = all(row.get('status') == 'COLLECTED' and row.get('cleanup_confirmed')
                       and row.get('probe', {}).get('collections_diagnostic', {}).get('state') == 'EXITED'
                       and type(row['probe']['collections_diagnostic'].get('returncode')) is int
                       and ((row['probe']['collections_status'] == 'COLLECTED'
                             and row['probe']['collections_diagnostic']['returncode'] == 0)
                            or (row['probe']['collections_status'] == 'COMMAND_FAILED'
                                and row['probe']['collections_diagnostic']['returncode'] != 0))
                       for row in pair)
        original_ok = pair[0].get('probe', {}).get('collections_status') == 'COLLECTED'
        tmp_ok = pair[1].get('probe', {}).get('collections_status') == 'COLLECTED'
        if not observed or not tmp_ok:
            comparisons[kind] = 'INCOMPLETE'
            complete = False
        elif original_ok:
            comparisons[kind] = 'BOTH_SUCCEEDED'
        else:
            comparisons[kind] = 'TEMP_CACHE_SUCCEEDED'
    return comparisons, complete


def candidate_summary(row):
    """Candidate inventory only; neither runtime compatibility nor Phase 1 PASS."""
    try:
        if row['status'] != 'COLLECTED' or row['cleanup_confirmed'] is not True:
            return 'INCOMPLETE', 3
        probe = row['probe']
        diagnostic = probe['collections_diagnostic']
        if (probe['collections_status'] != 'COLLECTED'
                or diagnostic['state'] != 'EXITED'
                or type(diagnostic['returncode']) is not int
                or diagnostic['returncode'] != 0):
            return 'INCOMPLETE', 3
        collections = probe['collections']
        if not isinstance(collections, list):
            return 'INCOMPLETE', 3
        names = [entry['name'] for entry in collections]
        if (any(not isinstance(name, str) or not name for name in names)
                or len(names) != len(set(names))):
            return 'INCOMPLETE', 3
        assessment = assess('controller', probe)
        if assessment['unconfirmed']:
            return 'INCOMPLETE', 3
        if assessment['mismatches']:
            return 'CANDIDATE_MISMATCH', 4
        return 'CANDIDATE_INVENTORY_COLLECTED_ONLY', 0
    except (KeyError, TypeError, AttributeError):
        return 'INCOMPLETE', 3


def controller_checks_summary(row):
    """Check evidence completeness, then failures, then unresolved warnings."""
    status, code = candidate_summary(row)
    if code:
        return status, code
    try:
        probe = row['probe']
        checks = probe['controller_checks']
        if checks['schema'] != 'ruby-p1-controller-checks-r5':
            return 'INCOMPLETE', 3
        metadata = checks['metadata']
        if metadata['status'] not in ('MATCH', 'MISMATCH'):
            return 'INCOMPLETE', 3
        commands = checks['commands']
        required = ['pip_check', 'import_docker', 'import_requests', 'import_selinux']
        if metadata['status'] == 'MATCH':
            required += ['entry_load', 'molecule_drivers']
            if checks['driver_checks'] != 'EXECUTED':
                return 'INCOMPLETE', 3
        elif checks['driver_checks'] != 'SKIPPED_METADATA_NOT_MATCHED':
            return 'INCOMPLETE', 3
        observations = [commands[name] for name in required]
        observations.append(probe['collections_diagnostic'])
        for command in observations:
            if (command['state'] != 'EXITED' or type(command['returncode']) is not int
                    or type(command['stderr_bytes']) is not int or command['stderr_bytes'] < 0):
                return 'INCOMPLETE', 3
        if metadata['status'] == 'MISMATCH' or any(c['returncode'] != 0 for c in observations):
            return 'CONTROLLER_CHECKS_FAILED', 5
        count = commands['molecule_drivers']['docker_exact_lines']
        if type(count) is not int:
            return 'INCOMPLETE', 3
        if count != 1:
            return 'CONTROLLER_CHECKS_FAILED', 5
        if any(c['stderr_bytes'] for c in observations):
            return 'CONTROLLER_CHECKS_WARNING_REVIEW', 6
        return 'CONTROLLER_OFFLINE_CHECKS_PASSED_ONLY', 0
    except (KeyError, TypeError, AttributeError):
        return 'INCOMPLETE', 3


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['host', 'images', 'collections-diagnostic', 'controller-candidate', 'controller-checks'], default='host')
    parser.add_argument('--allow-pull', action='store_true')
    parser.add_argument('--ephemeral-ci', action='store_true')
    parser.add_argument('--output', required=True, help='New JSON path; never overwrites')
    args = parser.parse_args(argv)
    if args.allow_pull and args.mode == 'host':
        parser.error('--allow-pull requires an image mode')
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        parser.error('Linux x86_64 is required')
    if args.mode != 'host' and (not args.ephemeral_ci or os.environ.get('CIRCLECI') != 'true'):
        parser.error('images mode is restricted to an explicitly identified ephemeral CircleCI VM')
    output = Path(args.output)
    if not output.parent.is_dir():
        parser.error('output parent must already exist')
    try:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        parser.error('output is unavailable or already exists')
    report = {'schema': 'ruby-p1-environment-proposal-r1', 'run_id': uuid.uuid4().hex,
              'started_at': now(), 'mode': args.mode, 'allow_pull': args.allow_pull,
              'p1_02_complete': False, 'images': {}, 'status': 'INCOMPLETE',
              'remaining': ['lint_orb_execution_rules', 'become_and_facts', 'dnf_functionality',
                            'effective_repository_state', 'baseline_mount_and_sudo', 'CI_cost_limits']}
    exit_code = 3
    def interrupted(_number, _frame):
        raise Stop('INTERRUPTED')
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    try:
        report['host'] = host_inventory()
        report['script_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        if args.mode == 'host':
            report['status'], exit_code = 'HOST_COLLECTED_ONLY', 0
        else:
            st = os.stat('/var/run/docker.sock')
            if not stat.S_ISSOCK(st.st_mode) or st.st_uid != 0:
                raise Stop('LOCAL_DOCKER_SOCKET_NOT_CONFIRMED')
            deadline = time.monotonic() + 1200
            version_fmt = ('{"client":{{json .Client.Version}},"server":{{json .Server.Version}},'
                           '"os":{{json .Server.Os}},"arch":{{json .Server.Arch}}}')
            report['docker'] = parsed(DOCKER + ['version', '--format', version_fmt], deadline=deadline)
            source = Path(__file__).with_name('container_probe.py').read_text()
            report['container_probe_sha256'] = hashlib.sha256(source.encode()).hexdigest()
            if args.mode == 'controller-checks':
                checks_source = Path(__file__).with_name('controller_checks.py').read_text()
                report['controller_checks_sha256'] = hashlib.sha256(checks_source.encode()).hexdigest()
                source = checks_source + '\n' + source
                report['combined_probe_sha256'] = hashlib.sha256(source.encode()).hexdigest()
            if args.mode in ('controller-candidate', 'controller-checks'):
                report['expected_packages'] = dict(EXPECTED)
                report['expected_collections'] = dict(COLLECTIONS)
                report['expected_config_digest'] = CANDIDATE_CONFIG_DIGEST
                report['remaining'] += ['candidate_pip_check', 'candidate_molecule_driver',
                                        'candidate_target_smoke', 'stderr_warning_review']
                extra = {'controller_checks': True} if args.mode == 'controller-checks' else {}
                report['images']['controller'] = collect_image(
                    'controller', CANDIDATE_CONTROLLER, args.allow_pull, report['run_id'],
                    deadline, source, galaxy_cache='tmp',
                    expected_image_id=CANDIDATE_CONFIG_DIGEST, **extra)
                summarize = controller_checks_summary if args.mode == 'controller-checks' else candidate_summary
                report['status'], exit_code = summarize(report['images']['controller'])
                if args.mode == 'controller-checks':
                    report['remaining'] += ['controller_warning_review', 'full_molecule_target_runtime']
                    if exit_code in (0, 6):
                        report['remaining'].remove('candidate_pip_check')
                        report['remaining'].remove('candidate_molecule_driver')
                    if exit_code == 0:
                        report['remaining'].remove('stderr_warning_review')
                        report['remaining'].remove('controller_warning_review')
                return exit_code
            if args.mode == 'collections-diagnostic':
                for kind, image in DIAGNOSTIC_IMAGES.items():
                    for cache_mode in ('original', 'tmp'):
                        key = kind + '_' + cache_mode
                        print('Inspecting ' + key, flush=True)
                        report['images'][key] = collect_image(
                            kind, image, args.allow_pull and cache_mode == 'original',
                            report['run_id'] + '-' + cache_mode, deadline, source,
                            galaxy_cache=None if cache_mode == 'original' else 'tmp')
                        if report['images'][key]['status'] != 'COLLECTED' or not report['images'][key]['cleanup_confirmed']:
                            raise Stop('DIAGNOSTIC_COLLECTION_OR_CLEANUP_FAILED')
                report['comparisons'], complete = diagnostic_summary(report['images'])
                report['status'] = 'DIAGNOSTIC_COLLECTED_ONLY' if complete else 'INCOMPLETE'
                exit_code = 0 if complete else 3
                return exit_code
            for kind, image in IMAGES.items():
                print('Inspecting ' + kind, flush=True)
                report['images'][kind] = collect_image(kind, image, args.allow_pull,
                                                       report['run_id'], deadline, source)
            rows = list(report['images'].values())
            incomplete = any(r['status'] != 'COLLECTED' or not r['cleanup_confirmed'] or
                             r.get('assessment', {}).get('unconfirmed') for r in rows)
            mismatch = any(r.get('assessment', {}).get('mismatches') for r in rows)
            report['status'] = 'INCOMPLETE' if incomplete else ('CANDIDATE_MISMATCH' if mismatch else 'INVENTORY_COLLECTED_ONLY')
            exit_code = 3 if incomplete else (4 if mismatch else 0)
    except Stop as exc:
        report['error_code'] = str(exc)
    except (OSError, ValueError, TypeError, KeyError):
        report['error_code'] = 'LOCAL_PRECONDITION_OR_SCHEMA_ERROR'
    finally:
        report['finished_at'] = now()
        report['exit_code'] = exit_code
        with os.fdopen(fd, 'w') as f:
            json.dump(report, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write('\n')
        print(json.dumps({'status': report['status'], 'exit_code': exit_code,
                          'p1_02_complete': False}), flush=True)
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
