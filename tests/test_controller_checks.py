"""Offline checks for disclosure, dependency errors, ambiguity and CI boundaries."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


c = load('checks', 'scripts/p1/controller_checks.py')
i = load('inventory', 'scripts/p1/container_probe.py')
p = load('runner', 'scripts/p1/env_probe.py')
c.warning_facts = i.warning_facts


def distribution(name='molecule-plugins', requirements=None, entry=True):
    return SimpleNamespace(metadata={'Name': name}, requires=requirements or [
        'molecule>=25.1.0', 'docker>=4.3.1; extra=="docker"',
        'requests; extra=="docker"', 'selinux; sys_platform=="linux" and extra=="docker"',
        'selinux; sys_platform=="linux2" and extra=="docker"',
        'google-auth>=2.28.2; extra=="gce"'],
        entry_points=[SimpleNamespace(group='molecule.driver', name='docker', value=c.EXPECTED_ENTRY)] if entry else [])


def command(rc=0, stderr=0):
    return {'state': 'EXITED', 'returncode': rc, 'stderr_bytes': stderr}


def compatible_row():
    commands = {name: command() for name in ('pip_check', 'import_docker', 'import_requests',
                                           'import_selinux', 'entry_load', 'molecule_drivers')}
    commands['molecule_drivers']['docker_exact_lines'] = 1
    return {'status': 'COLLECTED', 'cleanup_confirmed': True, 'probe': {
        'arch': 'x86_64', 'python': '3.14.10', 'packages': dict(p.EXPECTED),
        'collections_status': 'COLLECTED', 'collections_diagnostic': command(),
        'collections': [{'name': n, 'version': v} for n, v in p.COLLECTIONS.items()],
        'controller_checks': {'schema': c.CHECK_SCHEMA, 'metadata': {'status': 'MATCH'},
                              'driver_checks': 'EXECUTED', 'commands': commands}}}


class ControllerChecksTests(unittest.TestCase):
    def metadata(self, dist=None, dists=None, versions=None):
        dist = dist or distribution()
        versions = versions or {'molecule': '26.11.0', 'docker': '7.2.0',
                                'requests': '2.32.5', 'selinux': '0.3.0'}
        def version(name):
            if versions[name] is None:
                raise c.md.PackageNotFoundError(name)
            return versions[name]
        with patch.object(c.md, 'distribution', return_value=dist), patch.object(c.md, 'distributions', return_value=dists or [dist]), patch.object(c.md, 'version', side_effect=version):
            return c.dependency_metadata()

    def test_docker_extra_includes_linux_selinux_but_not_gce_requirements(self):
        result = self.metadata()
        self.assertEqual(result['status'], 'MATCH')
        self.assertEqual(set(result['versions']), set(c.REQUIRED))
        self.assertNotIn('google-auth', json.dumps(result))

    def test_missing_extra_or_below_minimum_is_not_a_pip_check_pass(self):
        for key, value in [('selinux', None), ('docker', '4.0.0'), ('requests', None)]:
            versions = {'molecule': '26.11.0', 'docker': '7.2.0', 'requests': '2.32.5', 'selinux': '0.3.0'}
            versions[key] = value
            result = self.metadata(versions=versions)
            self.assertEqual(result['status'], 'MISMATCH')

    def test_duplicate_entries_legacy_or_duplicate_distribution_are_rejected(self):
        base = distribution()
        for extra in [distribution(), distribution('molecule-docker'), distribution('molecule_docker', entry=False), distribution('other-provider')]:
            self.assertEqual(self.metadata(dists=[base, extra])['status'], 'MISMATCH')

    def test_unknown_requirement_direct_url_and_invalid_metadata_are_private(self):
        for req in ['requests @ https://user:PRIVATE_FIXTURE@example.invalid/a', 'PRIVATE_FIXTURE>=1', 'not valid PRIVATE_FIXTURE']:
            result = self.metadata(dist=distribution(requirements=[req]))
            self.assertEqual(result['status'], 'INCOMPLETE')
            self.assertNotIn('PRIVATE_FIXTURE', json.dumps(result))
            self.assertNotIn('example.invalid', json.dumps(result))

    def test_unexpected_entry_value_is_never_emitted(self):
        dist = distribution()
        dist.entry_points[0].value = 'PRIVATE_FIXTURE:Secret'
        result = self.metadata(dist=dist)
        self.assertEqual(result['status'], 'MISMATCH')
        self.assertNotIn('PRIVATE_FIXTURE', json.dumps(result))

    def test_metadata_failures_skip_loading_and_cli(self):
        for state in ['MISMATCH', 'INCOMPLETE']:
            with patch.object(c, 'dependency_metadata', return_value={'status': state}), patch.object(c, 'check_command', return_value=(command(), b'')) as run:
                result = c.controller_checks()
            self.assertEqual(result['driver_checks'], 'SKIPPED_METADATA_NOT_MATCHED')
            self.assertEqual(run.call_count, 4)
            self.assertFalse(any('molecule' in call.args[0] for call in run.call_args_list))

    def test_cli_uses_same_interpreter_and_exact_docker_line(self):
        for output, count in [(b'delegated\ndocker\npodman\n', 1), (b'docker-other\n', 0), (b'docker\ndocker\n', 2)]:
            with patch.object(c, 'dependency_metadata', return_value={'status': 'MATCH'}), patch.object(c, 'check_command', return_value=(command(), output)) as run:
                result = c.controller_checks()
            self.assertEqual(run.call_args.args[0], [c.sys.executable, '-m', 'molecule', 'drivers', '--format', 'simple'])
            self.assertEqual(result['commands']['molecule_drivers']['docker_exact_lines'], count)
            self.assertEqual(run.call_count, 6)

    def test_raw_output_and_arbitrary_paths_never_leave_diagnostics(self):
        stderr = b"[Errno 30] Read-only file system: '/home/circleci/.ansible/PRIVATE_FIXTURE' https://private.invalid/PRIVATE_FIXTURE"
        with patch.object(c.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'PRIVATE_FIXTURE', stderr)):
            result, data = c.check_command(['fixture'])
        self.assertEqual(data, b'')
        self.assertEqual(result['stderr_hints'], ['READ_ONLY_FILESYSTEM'])
        self.assertEqual(result['stderr_path_classes'], ['CIRCLECI_ANSIBLE_HOME'])
        self.assertNotIn('PRIVATE_FIXTURE', json.dumps(result))
        self.assertNotIn('private.invalid', json.dumps(result))

    def test_timeout_os_error_and_excessive_output_stay_incomplete(self):
        for error, expected in [(subprocess.TimeoutExpired('PRIVATE_FIXTURE', 15, stderr=b'PRIVATE_FIXTURE'), 'TIMEOUT'), (PermissionError(13, 'PRIVATE_FIXTURE'), 'OS_ERROR')]:
            with patch.object(c.subprocess, 'run', side_effect=error):
                result, data = c.check_command(['fixture'])
            self.assertEqual(result['state'], expected)
            self.assertEqual(data, b'')
            self.assertNotIn('PRIVATE_FIXTURE', json.dumps(result))
        with patch.object(c.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'x' * (1024*1024+1), b'')):
            result, data = c.check_command(['fixture'])
        self.assertEqual(result['state'], 'OUTPUT_TOO_LARGE')
        self.assertEqual(data, b'')

    def test_success_is_limited_to_offline_checks(self):
        self.assertEqual(p.controller_checks_summary(compatible_row()), ('CONTROLLER_OFFLINE_CHECKS_PASSED_ONLY', 0))

    def test_each_command_failure_or_missing_evidence_is_detected(self):
        for name in compatible_row()['probe']['controller_checks']['commands']:
            for defect in ['failure', 'missing', 'timeout', 'boolean', 'missing_stderr']:
                row = compatible_row()
                commands = row['probe']['controller_checks']['commands']
                if defect == 'failure': commands[name]['returncode'] = 1
                elif defect == 'missing': del commands[name]
                elif defect == 'timeout': commands[name]['state'] = 'TIMEOUT'
                elif defect == 'boolean': commands[name]['returncode'] = False
                else: del commands[name]['stderr_bytes']
                self.assertEqual(p.controller_checks_summary(row)[1], 5 if defect == 'failure' else 3)

    def test_warning_on_any_command_or_collection_never_passes(self):
        for name in ['collections', *compatible_row()['probe']['controller_checks']['commands']]:
            row = compatible_row()
            cmd = row['probe']['collections_diagnostic'] if name == 'collections' else row['probe']['controller_checks']['commands'][name]
            cmd['stderr_bytes'] = 359
            self.assertEqual(p.controller_checks_summary(row), ('CONTROLLER_CHECKS_WARNING_REVIEW', 6))

    def test_cleanup_or_version_mismatch_cannot_be_overridden(self):
        row = compatible_row(); row['cleanup_confirmed'] = False
        self.assertEqual(p.controller_checks_summary(row)[1], 3)
        row = compatible_row(); row['probe']['packages']['molecule-plugins'] = '26.10.12'
        self.assertEqual(p.controller_checks_summary(row)[1], 4)

    def test_missing_or_duplicate_cli_docker_cannot_pass(self):
        for count in [0, 2, False]:
            row = compatible_row()
            row['probe']['controller_checks']['commands']['molecule_drivers']['docker_exact_lines'] = count
            self.assertNotEqual(p.controller_checks_summary(row)[1], 0)

    def test_new_mode_makes_one_container_with_fixed_digest_and_keeps_phase_open(self):
        signals = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        try:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'evidence.json'
                real_stat = p.os.stat
                def fake_stat(path, *args, **kwargs):
                    return SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=0) if str(path) == '/var/run/docker.sock' else real_stat(path, *args, **kwargs)
                with patch.dict(os.environ, {'CIRCLECI': 'true'}), patch.object(p, 'host_inventory', return_value={}), patch.object(p.os, 'stat', side_effect=fake_stat), patch.object(p, 'parsed', return_value={}), patch.object(p, 'collect_image', return_value=compatible_row()) as collect, contextlib.redirect_stdout(io.StringIO()):
                    rc = p.main(['--mode','controller-checks','--allow-pull','--ephemeral-ci','--output',str(output)])
                report = json.loads(output.read_text())
                self.assertEqual(rc, 0)
                self.assertEqual(collect.call_count, 1)
                self.assertEqual(collect.call_args.args[:3], ('controller', p.CANDIDATE_CONTROLLER, True))
                self.assertEqual(collect.call_args.kwargs, {'galaxy_cache':'tmp', 'expected_image_id':p.CANDIDATE_CONFIG_DIGEST, 'controller_checks':True})
                compile(collect.call_args.args[5], '<combined probe>', 'exec')
                self.assertFalse(report['p1_02_complete'])
                self.assertIn('candidate_target_smoke', report['remaining'])
                self.assertNotIn('candidate_pip_check', report['remaining'])
        finally:
            for sig, handler in signals.items(): signal.signal(sig, handler)

    def test_controller_checks_keep_network_rootfs_socket_boundaries(self):
        info = {'id':p.CANDIDATE_CONFIG_DIGEST, 'os':'linux', 'arch':'amd64'}
        with patch.object(p, 'parsed', side_effect=[info, compatible_row()['probe']]) as parsed, patch.object(p, 'registry_identity', return_value={}), patch.object(p, 'cleanup', return_value=True):
            p.collect_image('controller', p.CANDIDATE_CONTROLLER, False, 'fixture', None, 'pass', galaxy_cache='tmp', expected_image_id=p.CANDIDATE_CONFIG_DIGEST, controller_checks=True)
        args = parsed.call_args.args[0]
        for flag in ['--read-only', '--network', 'none', '--cap-drop', 'ALL', 'no-new-privileges', 'RUBY_P1_CONTROLLER_CHECKS=1']:
            self.assertIn(flag, args)
        for flag in ['--privileged','--mount','-v','--user']:
            self.assertNotIn(flag,args)
        self.assertEqual(args[-2], p.CANDIDATE_CONFIG_DIGEST)


if __name__ == '__main__':
    unittest.main()
