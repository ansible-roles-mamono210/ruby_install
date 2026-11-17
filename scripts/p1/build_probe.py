#!/usr/bin/env python3
"""Host boundary for one explicitly approved Ruby 3.4.12 with Rust present evaluation build."""
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
HELPERS = {'runtime_smoke.py': '450a33babab510d9d529e309cbfd0ea1a9d76ef4728f1e6190a6a0f41935ecc5', 'env_probe.py': '7773d3dfd2a9b4d9f77d1f45ad37c6ce2810752dafaebf57780fdd2089ef80b9', 'dependency_probe.py': '240c2304eb28c8d769cb6d5cfaf2ae964175e50339d9debf358e7331a8807018', 'dependency_container_probe.py': '2118deac29ca85c050e4cee8291b3a062f7d9646fe0c69739562794922904b1d', 'install_probe.py': 'e22b2ee47ba07e88260d1e5877d08acfdfdcaa030f2eea4f98ffb470ad273ab5', 'install_container_probe.py': 'a6e0acd458cc03ba90bccb552f735957681c73852f3e0d80cee4aac7ed2c9fd9', 'source_container_probe.py': 'd264f2d1cb6cfbaf7c8b4f9d8530e2e3586a99ec9abf8e73d12a48ab1dad35a8', 'build_container_probe.py': 'adc25df0317a8eaef0531a2b343b0a46d2c90773f36f7efa2db39e587008174d', 'rust_install_probe.py': '2074e1cb3cd9ad2b0295e7acef7a88beaba9dddf0da6bb847fc5683e103835a6', 'rust_install_container_probe.py': 'de4dd9186d6da8ca69ae821aab5169e637b17c130d9e8d104f76a9fe589c2a0a'}


class Stop(Exception):
    pass


def load(name):
    path = ROOT / (name + '.py')
    if path.name not in HELPERS or hashlib.sha256(path.read_bytes()).hexdigest() != HELPERS[path.name]:
        raise Stop('HELPER_CHANGED')
    spec = importlib.util.spec_from_file_location('r39_' + name, path)
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
        '--env', 'RUBY_P1_BUILD_PROBE=r39', '--entrypoint', '/usr/bin/python3',
        '-i', runtime.TARGET_CONFIG, '-I', '-B', '-']


def bundle(plan_text):
    text = 'import types, json\n'
    for variable, name in (('_dependency', 'dependency_container_probe.py'),
                            ('_installer', 'install_container_probe.py'),
                            ('_source', 'source_container_probe.py'),
                            ('_rust_worker', 'rust_install_container_probe.py')):
        text += variable + ' = types.ModuleType(' + repr('r39' + variable) + ')\n'
        text += 'exec(' + repr((ROOT / name).read_text()) + ', ' + variable + '.__dict__)\n'
    text += '_dependency.PACKAGES = ' + repr(load('rust_install_probe').PACKAGES) + '\n'
    text += '_expected = json.loads(' + repr(plan_text) + ')\n'
    return text + (ROOT / 'build_container_probe.py').read_text()


def validate(value, expected, worker, installer, install_host, dependency_host, dependency):
    if (type(value) is not dict or value.get('schema') != worker.SCHEMA
            or value.get('status') != worker.SUCCESS or value.get('stage') != 'finished'
            or value.get('condition') != {'ruby': worker.VERSION, 'prefix': worker.PREFIX,
                'documentation': True, 'rust': True, 'make_jobs': 1}
            or any(value['condition'].get(k) is not True for k in ('documentation', 'rust'))
            or type(value['condition'].get('make_jobs')) is not int
            or value.get('configure_argv') != list(worker.CONFIGURE)
            or any(value.get(k) is not False for k in ('p1_04_complete', 'phase1_complete',
                   'role_verified', 'idempotence_verified', 'full_workspace_retained'))
            or any(value.get(k) is not True for k in ('ruby_build_verified', 'unknown_option_rejected',
                   'rust_present_after_dependencies', 'public_commands_unchanged',
                   'rpm_and_repo_state_unchanged_by_build', 'ci_container_cleanup_required'))
            or not install_host.number(value.get('elapsed_seconds'), 2310)):
        raise Stop('BUILD_WORKER_SCHEMA')
    rust_host = load('rust_install_probe')
    rust_worker = load('rust_install_container_probe')
    try:
        rust_host.validate(value['dependencies'], expected, rust_worker, installer, dependency_host, dependency)
    except rust_host.Stop as error:
        raise Stop('RUST_DEPENDENCY_SCHEMA') from error
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
    if (settings.get('USE_YJIT') != 0 or settings.get('USE_RJIT') != 0
            or settings.get('configure_summary_jit_disabled') is not True
            or settings.get('makefile_values') != {'prefix': worker.PREFIX, 'ENABLE_SHARED': 'yes',
                'YJIT_SUPPORT': 'no', 'RJIT_SUPPORT': 'no', 'DOCTARGETS': 'rdoc nodoc',
                'INSTALLDOC': 'all', 'EXTOUT': '.ext'}):
        raise Stop('BUILD_SETTING_SCHEMA')
    docs = value['documentation']
    if (type(docs) is not dict or docs.get('enabled') is not True
            or docs.get('standard_String_verified') is not True
            or docs.get('other_stores_disabled') is not True
            or docs != {'enabled': True, 'system_dir': worker.PREFIX + '/share/ri/3.4.0/system',
                        'standard_String_verified': True, 'other_stores_disabled': True}):
        raise Stop('BUILD_DOCUMENTATION_SCHEMA')
    names = ['configure-negative', 'configure', 'make', 'install', 'runtime']
    names += ['command-' + n for n in worker.COMMANDS] + ['ri-String']
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
    resources = value['resources']
    if ('memory_events' not in resources or (resources['memory_events'] is not None and
            checked_memory_events(resources['memory_events']) is None)):
        raise Stop('BUILD_MEMORY_EVENTS_SCHEMA')
    if checked_memory_phases(resources.get('memory_phases'), complete=True) is None:
        raise Stop('BUILD_MEMORY_PHASES_INCOMPLETE')


def checked_memory_events(value):
    required = {'low', 'high', 'max', 'oom', 'oom_kill'}
    if (type(value) is dict and set(value) == {'source', 'counters'} and
            value['source'] in ('/sys/fs/cgroup/memory.events.local', '/sys/fs/cgroup/memory.events') and
            type(value['counters']) is dict and
            required <= set(value['counters']) <= required | {'oom_group_kill'} and
            all(type(n) is int and 0 <= n <= 2 ** 63 - 1 for n in value['counters'].values())):
        return {'source': value['source'], 'counters': dict(value['counters'])}
    return None


PHASE_NAMES = (['dependencies', 'download', 'extract', 'configure-negative',
                'configure', 'make', 'install', 'runtime'] +
               ['command-' + name for name in ('ruby', 'gem', 'bundle', 'bundler',
                 'irb', 'erb', 'rdoc', 'ri', 'rake')] + ['ri-String'])
STAT_KEYS = {'anon', 'file', 'kernel', 'kernel_stack', 'pagetables', 'sock', 'shmem',
             'file_mapped', 'file_dirty', 'file_writeback', 'slab_reclaimable', 'slab_unreclaimable'}


def memory_number(value):
    return type(value) is int and 0 <= value <= 2 ** 63 - 1


def valid_snapshot(value):
    if (type(value) is not dict or set(value) != {'at_seconds', 'current_bytes',
            'lifetime_peak_bytes', 'stat_bytes', 'events'}):
        return False
    stamp = value['at_seconds']
    if not (type(stamp) in (int, float) and math.isfinite(stamp) and 0 <= stamp <= 900):
        return False
    if any(value[k] is not None and not memory_number(value[k])
           for k in ('current_bytes', 'lifetime_peak_bytes')):
        return False
    stats = value['stat_bytes']
    if stats is not None and (type(stats) is not dict or
            not {'anon', 'file'} <= set(stats) <= STAT_KEYS or
            not all(memory_number(v) for v in stats.values())):
        return False
    return value['events'] is None or checked_memory_events(value['events']) is not None


def checked_memory_phases(value, complete=False):
    if type(value) is not list or len(value) > len(PHASE_NAMES):
        return None
    if complete and len(value) != len(PHASE_NAMES):
        return None
    previous = 0
    for index, row in enumerate(value):
        if (type(row) is not dict or set(row) != {'name', 'sample_count',
                'current_unavailable_samples', 'current_peak_bytes_sampled',
                'before', 'after', 'events_delta', 'completed'} or
                row['name'] != PHASE_NAMES[index] or type(row['completed']) is not bool):
            return None
        if not valid_snapshot(row['before']) or not valid_snapshot(row['after']):
            return None
        before, after = row['before'], row['after']
        if not previous <= before['at_seconds'] <= after['at_seconds']:
            return None
        previous = after['at_seconds']
        if (not memory_number(row['sample_count']) or not 2 <= row['sample_count'] <= 10000 or
                not memory_number(row['current_unavailable_samples']) or
                row['current_unavailable_samples'] > row['sample_count']):
            return None
        peak = row['current_peak_bytes_sampled']
        currents = [x['current_bytes'] for x in (before, after) if x['current_bytes'] is not None]
        if (peak is not None and not memory_number(peak)) or (currents and (peak is None or peak < max(currents))):
            return None
        a, b = before['events'], after['events']
        comparable = (a is not None and b is not None and a['source'] == b['source'] and
                      set(a['counters']) == set(b['counters']) and
                      all(b['counters'][k] >= v for k, v in a['counters'].items()))
        expected = {k: b['counters'][k] - v for k, v in a['counters'].items()} if comparable else None
        delta = row['events_delta']
        if (delta != expected or (delta is not None and
                (type(delta) is not dict or not all(memory_number(v) for v in delta.values())))):
            return None
        if complete and (not row['completed'] or expected is None or
                any(x[k] is None for x in (before, after)
                    for k in ('current_bytes', 'lifetime_peak_bytes'))):
            return None
    # Every field has been allowlisted and bounded above; preserve no arbitrary strings.
    return value


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
        if 'memory_events' in resources:
            events = checked_memory_events(resources['memory_events'])
            if resources['memory_events'] is None or events is not None:
                kept['memory_events'] = events
        phases = checked_memory_phases(resources.get('memory_phases'))
        if phases is not None:
            kept['memory_phases'] = phases
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
    if type(value) is not dict or value.get('schema') != 'ruby-p1-build-container-r39':
        return {'reason': 'UNREADABLE_WORKER_RESULT'}
    result = {}
    for key in ('stage', 'reason', 'error_type'):
        item = value.get(key)
        if type(item) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,100}', item):
            result[key] = item
    if type(value.get('runs')) is list and len(value['runs']) <= 15:
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
    for flag in ('allow-pull', 'allow-install', 'allow-ci430-replacements',
                 'allow-ruby-3412-rust-build', 'allow-rust-install', 'allow-memory-diagnostic', 'ephemeral-ci'):
        parser.add_argument('--' + flag, action='store_true')
    args = parser.parse_args(argv)
    if (not all((args.allow_pull, args.allow_install, args.allow_ci430_replacements,
                 args.allow_ruby_3412_rust_build, args.allow_rust_install, args.allow_memory_diagnostic, args.ephemeral_ci))
            or os.environ.get('CIRCLECI') != 'true' or os.environ.get('CIRCLE_BRANCH') != BRANCH
            or platform.system() != 'Linux' or platform.machine() != 'x86_64'):
        print('STOP: EXPLICIT_EPHEMERAL_RUBY_BUILD_APPROVAL_REQUIRED')
        return 3
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        print('STOP: OUTPUT_UNAVAILABLE_OR_EXISTS')
        return 3
    report = {'schema': 'ruby-p1-build-run-r39', 'status': 'INCOMPLETE', 'stage': 'preflight',
              'p1_04_complete': False, 'phase1_complete': False, 'cleanup_confirmed': None}
    possible, runtime = False, None
    run_id = uuid.uuid4().hex
    name = 'ruby-p1-' + run_id + '-build-r39'
    handlers = {}
    try:
        def interrupted(_sig, _frame):
            raise Stop('INTERRUPTED')
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.signal(sig, interrupted)
        runtime, inventory = load('runtime_smoke'), load('env_probe')
        worker, installer = load('build_container_probe'), load('install_container_probe')
        install_host, dependency_host = load('install_probe'), load('dependency_probe')
        rust_host, rust_worker = load('rust_install_probe'), load('rust_install_container_probe')
        dependency = rust_host.profile(load('dependency_container_probe'))
        load('source_container_probe')
        plan_text = (ROOT / 'ci430_dependency_plan.json').read_text()
        if hashlib.sha256(plan_text.encode()).hexdigest() != rust_host.HELPERS['ci430_dependency_plan.json']:
            raise Stop('BASELINE_PLAN_CHANGED')
        expected = json.loads(plan_text)
        socket = os.stat('/var/run/docker.sock')
        if not stat.S_ISSOCK(socket.st_mode) or socket.st_uid != 0:
            raise Stop('LOCAL_ROOT_DOCKER_SOCKET_REQUIRED')
        report['started_at'] = inventory.now()
        report['source_sha256'] = dict(HELPERS, **{'build_probe.py': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                      'ci430_dependency_plan.json': rust_host.HELPERS['ci430_dependency_plan.json']})
        end = time.monotonic() + 840
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
            capture_output=True, timeout=min(750, max(1, end - time.monotonic())), check=False)
        report['command'] = {'returncode': process.returncode, 'stdout_bytes': len(process.stdout.encode()),
                             'stderr_bytes': len(process.stderr.encode())}
        if len(process.stdout.encode()) > 1048576:
            raise Stop('WORKER_OUTPUT_LIMIT')
        value = json.loads(process.stdout)
        report['failure'] = diagnostics(value)
        if type(value) is dict and type(value.get('dependencies')) is dict:
            report['failure']['dependency_failure'] = rust_host.failure(value['dependencies'], rust_worker, installer)
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
    return 0 if report['status'] == 'RUBY_3412_DOCS_ON_RUST_PRESENT_BUILD_VERIFIED' else 3


if __name__ == '__main__':
    raise SystemExit(main())
