#!/usr/bin/env python3
"""One gated fixed-controller/CS9 Ansible acquisition evaluation, no Role run."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent
FILES = ('ansible_download_probe.py', 'ansible_download_fixture.py',
         'ansible_download_controller.py', 'ansible_download_callback.py', 'ansible_download.yml')
HELPERS = {
    'runtime_smoke.py': '450a33babab510d9d529e309cbfd0ea1a9d76ef4728f1e6190a6a0f41935ecc5',
    'env_probe.py': '7773d3dfd2a9b4d9f77d1f45ad37c6ce2810752dafaebf57780fdd2089ef80b9',
    'download_guard_fixture.py': '2efaa5cf40127ed5421eab9a16e7e2925d46de5087dacde890ad02672f703896',
}


class Stop(Exception):
    pass


def load(name):
    p = ROOT / (name + '.py')
    if p.name in HELPERS and hashlib.sha256(p.read_bytes()).hexdigest() != HELPERS[p.name]:
        raise Stop('HELPER_CHANGED')
    spec = importlib.util.spec_from_file_location('r49_' + name, p)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


class Channel:
    def __init__(self, process, deadline):
        self.process, self.deadline, self.buffer = process, deadline, b''

    def exchange(self, request):
        data = json.dumps(request).encode() + b'\n'
        if len(data) > 32768:
            raise Stop('REQUEST_SIZE')
        self.process.stdin.write(data)
        self.process.stdin.flush()
        until = min(self.deadline, time.monotonic() + 15)
        while b'\n' not in self.buffer:
            wait = until - time.monotonic()
            if wait <= 0 or not select.select([self.process.stdout], [], [], wait)[0]:
                raise Stop('FIXTURE_TIMEOUT')
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                raise Stop('FIXTURE_EOF')
            self.buffer += chunk
            if len(self.buffer) > 8192:
                raise Stop('FIXTURE_OUTPUT_SIZE')
        line, self.buffer = self.buffer.split(b'\n', 1)
        value = json.loads(line)
        if type(value) is not dict or value.get('state') == 'INCOMPLETE':
            raise Stop('FIXTURE_INCOMPLETE')
        return value


def validate_case(index, result, observed):
    matrix = load('ansible_download_fixture').MATRIX
    case, status, scheme = matrix[index]
    valid, mismatch = case == 'valid', case == 'checksum_mismatch'
    is_tls = case in ('untrusted_certificate', 'hostname_mismatch')
    publication = {'schema': 'ruby-p1-ansible-acquisition-case-r49',
                   'failure_stage': 'none' if valid else 'P1 checksum' if mismatch else 'P1 uri',
                   'http_status': -1 if is_tls else status, 'uri_failed': not (valid or mismatch),
                   'tls_verification_failed': is_tls, 'stat_ran': valid or mismatch,
                   'checksum_matches': valid, 'gate_reached': valid}
    events = [{'task': 'P1 uri', 'state': 'ok' if valid or mismatch else 'failed'}]
    if valid or mismatch:
        events += [{'task': 'P1 stat', 'state': 'ok'},
                   {'task': 'P1 checksum', 'state': 'ok' if valid else 'failed'}]
    events += ([{'task': 'P1 gate witness', 'state': 'ok'}] if valid else
               [{'task': 'P1 remember failure stage', 'state': 'ok'}])
    events += [{'task': 'P1 publish acquisition result', 'state': 'ok'}]
    wanted = {'schema': 'ruby-p1-ansible-acquisition-events-r49', 'status': 'RECORDED',
              'publication': publication, 'events': events}
    expected_observation = {'state': 'OBSERVED', 'index': index, 'case': case,
                            'response_status': status,
                            'sink_delta': {s: {'connections': 0, 'requests': 0} for s in ('http', 'https')},
                            'origin_connections': 1, 'origin_requests': 0 if is_tls else 1,
                            'file_exists': valid or mismatch, 'checksum_matches': valid, 'gate_marker': valid}
    # JSON exact comparison also rejects bools in place of numeric counters.
    if json.dumps(result, sort_keys=True) != json.dumps(wanted, sort_keys=True):
        raise Stop('ANSIBLE_CASE_MISMATCH')
    if json.dumps(observed, sort_keys=True) != json.dumps(expected_observation, sort_keys=True):
        raise Stop('NETWORK_OR_GATE_MISMATCH')


def exercise(channel, execute, rows=None):
    controller = load('ansible_download_controller')
    rows = [] if rows is None else rows
    for index in range(16):
        request = channel.exchange({'op': 'prepare', 'index': index})
        if set(request) != {'state', 'index', 'variables'} or request['state'] != 'PREPARED' or type(request['index']) is not int or request['index'] != index:
            raise Stop('PREPARE_SCHEMA')
        controller.validate_variables(request['variables'])
        result = execute(request['variables'])
        observed = channel.exchange({'op': 'finish', 'index': index})
        validate_case(index, result, observed)
        rows.append({'ansible': result, 'observation': observed})
    last = channel.exchange({'op': 'stop'})
    if last != {'state': 'FINISHED', 'temporary_directory_removed': True}:
        raise Stop('FIXTURE_CLEANUP')
    return rows


def target_args(runtime, name, run_id):
    code = ('import sys,types\nm=types.ModuleType("download_guard_fixture")\n'
            'sys.modules[m.__name__]=m\nexec(' + repr((ROOT / 'download_guard_fixture.py').read_text()) + ',m.__dict__)\n'
            'exec(compile(' + repr((ROOT / 'ansible_download_fixture.py').read_text()) + ',"<r49-fixture>","exec"))')
    return runtime.DOCKER + ['run', '--rm', '-i', '--pull=never', '--platform', 'linux/amd64',
                            '--name', name, '--label', 'ruby-p1.run=' + run_id,
                            '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                            '--security-opt', 'no-new-privileges', '--no-healthcheck',
                            '--user', '65534:65534', '--pids-limit', '128', '--memory', '512m',
                            '--memory-swap', '512m', '--cpus', '1',
                            '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777',
                            '--env', 'RUBY_P1_ANSIBLE_TARGET=r49', '--env', 'PYTHONDONTWRITEBYTECODE=1',
                            '--entrypoint', '/usr/bin/python3', runtime.TARGET_CONFIG, '-I', '-B', '-c', code]


def controller_args(runtime, name, run_id, directory, gid):
    return runtime.DOCKER + ['run', '-d', '--pull=never', '--platform', 'linux/amd64',
                            '--name', name, '--label', 'ruby-p1.run=' + run_id,
                            '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                            '--security-opt', 'no-new-privileges', '--no-healthcheck',
                            '--pids-limit', '128', '--memory', '1g', '--memory-swap', '1g', '--cpus', '1',
                            '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=128m', '--group-add', str(gid),
                            '--mount', 'type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock,readonly',
                            '--mount', 'type=bind,src=' + str(directory) + ',dst=/p1,readonly',
                            '--env', 'PYTHONDONTWRITEBYTECODE=1', '--entrypoint', 'python3',
                            runtime.CONTROLLER_CONFIG, '-I', '-B', '-c', 'import time;time.sleep(650)']


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    for f in ('allow-pull', 'ephemeral-ci', 'allow-ci-docker-api', 'allow-ansible-download'):
        parser.add_argument('--' + f, action='store_true')
    args = parser.parse_args(argv)
    report = {'schema': 'ruby-p1-ansible-download-r49', 'status': 'INCOMPLETE', 'stage': 'preflight',
              'role_verified': False, 'p1_04_complete': False, 'phase1_complete': False,
              'scope': 'actual_ansible_uri_stat_assert_with_fixture_gate_only', 'cleanup': {}}
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        print('STOP: OUTPUT_UNAVAILABLE_OR_EXISTS')
        return 3
    runtime, worker = None, None
    names, handlers = [], {}
    run_id = uuid.uuid4().hex
    try:
        def interrupted(*_):
            raise Stop('INTERRUPTED')
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.signal(sig, interrupted)
        if (not all((args.allow_pull, args.ephemeral_ci, args.allow_ci_docker_api, args.allow_ansible_download))
                or os.environ.get('CIRCLECI') != 'true'
                or os.environ.get('CIRCLE_BRANCH') != 'plan/ruby-100-p1-env-r1'
                or not re.fullmatch('[0-9a-f]{40}', os.environ.get('CIRCLE_SHA1', ''))
                or platform.system() != 'Linux' or platform.machine() != 'x86_64'):
            raise Stop('EXPLICIT_EPHEMERAL_CI_REQUIRED')
        sock = os.stat('/var/run/docker.sock')
        if not stat.S_ISSOCK(sock.st_mode) or sock.st_uid != 0:
            raise Stop('LOCAL_DOCKER_SOCKET_REQUIRED')
        runtime, inventory, tls = load('runtime_smoke'), load('env_probe'), load('download_guard_fixture')
        deadline = time.monotonic() + 600
        report.update(commit=os.environ['CIRCLE_SHA1'], run_id=run_id, started_at=inventory.now(), images={},
                      source_sha256={n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest() for n in FILES + tuple(HELPERS)})
        for kind, ref, config in (('controller', runtime.CONTROLLER, runtime.CONTROLLER_CONFIG),
                                  ('target', runtime.TARGET, runtime.TARGET_CONFIG)):
            report['stage'] = kind + '_pull'
            print(report['stage'], flush=True)
            runtime.command(runtime.DOCKER + ['pull', '--quiet', '--platform', 'linux/amd64', ref], deadline, 180)
            info = runtime.inspect_image(ref, config, deadline)
            identity = inventory.registry_identity(ref, info, deadline)
            expected = ref.split('@')[1] if kind == 'controller' else runtime.TARGET_MANIFEST
            if identity['platform_manifest_digest'] != expected or identity['config_digest'] != config:
                raise Stop('REGISTRY_MISMATCH')
            report['images'][kind] = identity
        target, controller = 'ruby-p1-' + run_id + '-fetch-target', 'ruby-p1-' + run_id + '-fetch-controller'
        with tempfile.TemporaryDirectory(prefix='ruby-p1-r49-') as directory:
            directory = Path(directory)
            directory.chmod(0o755)
            for n in FILES:
                dest = directory / n
                dest.write_bytes((ROOT / n).read_bytes())
                dest.chmod(0o444)
            certificate, key = tls.certificate_material()
            report['stage'] = 'target_fixture'
            names.append(target)
            worker = subprocess.Popen(target_args(runtime, target, run_id), stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            channel = Channel(worker, deadline)
            ready = channel.exchange({'certificate': certificate, 'key': key})
            del certificate, key
            if ready != {'state': 'READY', 'python': '3.9.19', 'uid': 65534, 'cases': 16}:
                raise Stop('TARGET_BASELINE')
            names.append(controller)
            runtime.command(controller_args(runtime, controller, run_id, directory, sock.st_gid), deadline)
            report['stage'] = 'ansible_matrix'

            def execute(variables):
                timeout = min(35, deadline - time.monotonic())
                if timeout <= 0:
                    raise Stop('TIME_LIMIT')
                p = subprocess.run(runtime.DOCKER + ['exec', '-i', controller, 'python3', '-B',
                                                    '/p1/ansible_download_controller.py'],
                                   input=json.dumps({'target': target, 'variables': variables}),
                                   capture_output=True, text=True, timeout=timeout, check=False)
                if p.returncode or p.stderr or len(p.stdout.encode()) > 8192:
                    raise Stop('CONTROLLER_EXECUTION_UNCONFIRMED')
                return json.loads(p.stdout)

            report['cases'] = []
            exercise(channel, execute, report['cases'])
            worker.stdin.close()
            worker.wait(timeout=15)
            if worker.returncode or worker.stderr.read(8193) or channel.buffer or worker.stdout.read(8193):
                raise Stop('FIXTURE_EXIT')
            report.update(status='ANSIBLE_ACQUISITION_MATRIX_PASSED', stage='finished',
                          controller={'python': '3.14.10', 'core': '2.21.6', 'community.docker': '5.4.0'},
                          target={'python': '3.9.19', 'os': 'centos-stream-9', 'uid': 65534},
                          temporary_tls_directory_removed=True)
    except BaseException as error:
        report['reason'] = str(error) if isinstance(error, Stop) else 'UNEXPECTED_OR_EXECUTION_ERROR'
        report['status'] = 'INCOMPLETE'
    finally:
        if worker and worker.poll() is None:
            try:
                worker.stdin.close()
                worker.wait(timeout=5)
            except Exception:
                try:
                    os.killpg(worker.pid, signal.SIGKILL)
                    worker.wait(timeout=5)
                except ProcessLookupError:
                    pass
        if runtime:
            for name in reversed(names):
                report['cleanup'][name.rsplit('-', 1)[-1]] = runtime.cleanup(name, run_id)
        report['cleanup_confirmed'] = bool(names) and all(report['cleanup'].values())
        if report['status'] != 'INCOMPLETE' and not report['cleanup_confirmed']:
            report.update(status='INCOMPLETE', reason='CLEANUP_UNCONFIRMED')
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        with os.fdopen(fd, 'w') as output:
            json.dump(report, output, sort_keys=True, indent=2)
            output.write('\n')
    print(report['status'], flush=True)
    return 0 if report['status'] == 'ANSIBLE_ACQUISITION_MATRIX_PASSED' else 3


if __name__ == '__main__':
    sys.exit(main())
