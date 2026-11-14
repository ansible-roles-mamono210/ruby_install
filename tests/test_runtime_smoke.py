"""Offline boundary, protocol, and failure tests; never contacts Docker/Ansible."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/p1' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


h = load('runtime_smoke')
t = load('runtime_target')
p = load('runtime_protocol')


def baseline():
    path = {'path': '/usr/sbin:/usr/bin', 'uid': 0, 'euid': 0,
            'commands': {k: None for k in p.COMMANDS}}
    flags = {'ro': False, 'noexec': False, 'nosuid': False, 'nodev': False}
    return {'schema': 'ruby-p1-runtime-baseline-r11', 'direct': path,
            'sudo_root': copy.deepcopy(path), 'mounts': {'/': flags, '/tmp': flags.copy()},
            'tools': {'sudo': True, 'visudo': True, 'useradd': True},
            'scope': 'stock_image_docker_exec_root_before_fixture'}


def valid_report():
    values = [dict(zip(p.FACTS, ('CentOS', '9', '3.9.19', 0))),
              {'assertion_passed': True}, baseline(),
              {'schema': 'ruby-p1-runtime-fixture-r11', 'user': 'ruby_p1_probe',
               'uid': 29999, 'sudo_rule_created': True, 'scope': 'disposable_target_only'},
              {'euid': 29999}, {'euid': 0}]
    return {'schema': 'ruby-p1-runtime-controller-r11', 'status': 'PASSED',
            'stage': 'finished', 'command': {'returncode': 0, 'stdout_bytes': 2000, 'stderr_bytes': 0},
            'ansible': {'schema': 'ruby-p1-ansible-runtime-r11', 'status': 'PASSED',
                        'measurements': dict(zip(p.TASKS, values))}}


class RuntimeProtocolTests(unittest.TestCase):
    def test_fixed_success_is_accepted(self):
        value = valid_report()
        self.assertIs(p.validate_report(value), value)

    def test_missing_task_wrong_identity_warning_and_extra_payload_rejected(self):
        changes = [lambda x: x['ansible']['measurements'].pop(p.TASKS[0]),
                   lambda x: x['ansible']['measurements'][p.TASKS[4]].update(euid=0),
                   lambda x: x['ansible']['measurements'][p.TASKS[5]].update(euid=29999),
                   lambda x: x['ansible']['measurements'][p.TASKS[5]].update(euid=False),
                   lambda x: x['command'].update(stderr_bytes=1),
                   lambda x: x['command'].update(returncode=1),
                   lambda x: x.update(raw_error='SECRET'),
                   lambda x: x['ansible']['measurements'][p.TASKS[0]].update(ansible_env={'SECRET': 'x'}),
                   lambda x: x['ansible']['measurements'][p.TASKS[0]].update(ansible_python_version='3.9.20'),
                   lambda x: x['ansible']['measurements'][p.TASKS[2]]['mounts']['/'].update(noexec=1),
                   lambda x: x['ansible']['measurements'][p.TASKS[2]]['direct'].update(path='a\nSECRET'),
                   lambda x: x['ansible']['measurements'][p.TASKS[2]]['tools'].update(sudo=1)]
        for change in changes:
            with self.subTest(change=change):
                value = valid_report()
                change(value)
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    p.validate_report(value)

    def test_callback_selection_discards_unrequested_facts(self):
        facts = valid_report()['ansible']['measurements'][p.TASKS[0]].copy()
        facts['ansible_env'] = {'SECRET': 'value'}
        value = p.selected(p.TASKS[0], {'ansible_facts': facts, 'invocation': {'SECRET': 'value'}})
        self.assertEqual(set(value), set(p.FACTS))
        self.assertNotIn('SECRET', json.dumps(value))

    def test_task_warning_or_stderr_is_not_known_collection_exception(self):
        for extra in ({'warnings': ['known warning']}, {'deprecations': ['old']}, {'stderr': 'x'}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                p.selected(p.TASKS[5], dict(rc=0, stdout='0', **extra))

    def test_null_commands_are_observations_not_failure(self):
        value = p.selected(p.TASKS[2], {'rc': 0, 'stdout': json.dumps(baseline())})
        self.assertIsNone(value['direct']['commands']['ruby'])


class RuntimeTargetTests(unittest.TestCase):
    def test_actual_mount_ancestor_and_escaped_name(self):
        data = ('1 0 0:1 / / rw - overlay overlay rw\n'
                '2 1 0:2 / /tmp rw,noexec - tmpfs tmpfs rw\n'
                '3 1 0:3 / /tmp2 rw - tmpfs tmpfs rw\n'
                '4 1 0:4 / /work\\040area ro - tmpfs tmpfs ro\n')
        self.assertTrue(t.mount_flags(data, '/tmp/build')['noexec'])
        self.assertFalse(t.mount_flags(data, '/tmp2/build')['noexec'])
        self.assertTrue(t.mount_flags(data, '/work area/build')['ro'])

    def test_mount_ambiguity_stops(self):
        row = '1 0 0:1 / / rw - overlay overlay rw\n'
        with self.assertRaises(ValueError):
            t.mount_flags(row + row, '/tmp')

    def test_fixture_requires_disposable_marker_before_any_changes(self):
        with patch.dict(t.os.environ, {}, clear=True), patch.object(t.sys, 'argv', ['x', 'fixture']), \
                patch.object(t, 'fixture') as fixture, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(t.main(), 3)
        fixture.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())['status'], 'REFUSED')

    def test_existing_uid_does_not_get_reused_or_modified(self):
        with patch.object(t.os, 'geteuid', return_value=0), \
                patch.object(t.Path, 'exists', return_value=False), \
                patch.object(t.Path, 'is_symlink', return_value=False), \
                patch.object(t.pwd, 'getpwnam', side_effect=KeyError), \
                patch.object(t.pwd, 'getpwuid', return_value=object()), patch.object(t, 'run') as run:
            with self.assertRaises(ValueError):
                t.fixture()
        run.assert_not_called()

    def test_existing_sudo_rule_never_overwritten(self):
        with patch.object(t.os, 'geteuid', return_value=0), \
                patch.object(t.Path, 'exists', return_value=True), patch.object(t, 'run') as run:
            with self.assertRaises(ValueError):
                t.fixture()
        run.assert_not_called()

    def test_target_error_text_not_persisted(self):
        with patch.dict(t.os.environ, {'RUBY_P1_TARGET_FIXTURE': '1'}), \
                patch.object(t.sys, 'argv', ['x', 'baseline']), \
                patch.object(t, 'baseline', side_effect=RuntimeError('SECRET')), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(t.main(), 3)
        self.assertNotIn('SECRET', out.getvalue())


class RuntimeHostTests(unittest.TestCase):
    def test_no_mutation_or_output_without_all_explicit_gates(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(h, 'command') as command, \
                contextlib.redirect_stdout(io.StringIO()):
            path = Path(tmp) / 'result.json'
            self.assertEqual(h.main(['--output', str(path)]), 3)
            self.assertFalse(path.exists())
        command.assert_not_called()

    def test_target_preserves_normal_mounts_and_sudo_capability(self):
        args = h.target_args('target', 'run')
        self.assertEqual(args[args.index('--network') + 1], 'none')
        self.assertIn(h.TARGET_CONFIG, args)
        for flag in ('--read-only', '--tmpfs', '--mount', '--privileged', '--cap-add', '--security-opt'):
            self.assertNotIn(flag, args)
        self.assertNotIn('/var/run/docker.sock', args[args.index('run') + 1:])

    def test_controller_socket_explicit_no_chmod_or_full_checkout(self):
        args = h.controller_args('controller', 'target', 'run', '/tmp/dedicated', 123)
        self.assertEqual(args[args.index('--group-add') + 1], '123')
        self.assertIn('type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock,readonly', args)
        self.assertIn('type=bind,src=/tmp/dedicated,dst=/p1,readonly', args)
        for flag in ('--read-only', '--cap-drop', 'ALL', 'no-new-privileges'):
            self.assertIn(flag, args)
        for forbidden in ('chmod', '--privileged', '/usr/bin/docker'):
            self.assertNotIn(forbidden, args)

    def test_image_volumes_null_and_empty_are_accepted_other_shapes_stop(self):
        value = {'id': h.TARGET_CONFIG, 'repo_digests': [h.TARGET], 'os': 'linux',
                 'arch': 'amd64', 'user': '', 'volumes': None}
        for volumes in (None, {}):
            value['volumes'] = volumes
            with patch.object(h, 'command', return_value=json.dumps(value)):
                self.assertEqual(h.inspect_image(h.TARGET, h.TARGET_CONFIG, 1)['volume_count'], 0)
        for volumes in ([], False, '', {'/var': {}}):
            value['volumes'] = volumes
            with patch.object(h, 'command', return_value=json.dumps(value)), self.assertRaises(h.Stop):
                h.inspect_image(h.TARGET, h.TARGET_CONFIG, 1)

    def test_command_errors_are_bounded_and_do_not_echo_secrets(self):
        cases = [(subprocess.CompletedProcess([], 1, 'SECRET', ''), 'COMMAND_EXIT_1'),
                 (subprocess.CompletedProcess([], 0, '', 'SECRET'), 'UNCLASSIFIED_STDERR')]
        for result, expected in cases:
            with patch.object(h.subprocess, 'run', return_value=result), self.assertRaises(h.Stop) as error:
                h.command(['x'], time.monotonic() + 5)
            self.assertEqual(str(error.exception), expected)

    def test_cleanup_only_removes_matching_ids_and_requires_absence(self):
        with patch.object(h, 'command', side_effect=['abcdef012345\n', 'abcdef012345\n', '']) as command:
            self.assertTrue(h.cleanup('known', 'runid'))
        self.assertIn('label=ruby-p1.run=runid', command.call_args_list[0].args[0])
        self.assertEqual(command.call_args_list[1].args[0], h.DOCKER + ['rm', '-f', 'abcdef012345'])
        with patch.object(h, 'command', return_value='bad id') as command:
            self.assertFalse(h.cleanup('known', 'runid'))
            self.assertEqual(command.call_count, 1)

    def test_playbook_scope_has_no_role_install_or_general_facts(self):
        play, = yaml.safe_load((ROOT / 'scripts/p1/runtime_smoke.yml').read_text())
        self.assertFalse(play['gather_facts'])
        self.assertNotIn('roles', play)
        self.assertEqual(tuple(task['name'] for task in play['tasks']), p.TASKS)
        setup = play['tasks'][0]['ansible.builtin.setup']
        self.assertEqual(set(setup['filter']), set(p.FACTS))
        self.assertIn('!min', setup['gather_subset'])
        self.assertIn('platform', setup['gather_subset'])
        self.assertTrue(all(task['no_log'] for task in play['tasks']))
        self.assertFalse(play['tasks'][-2]['become'])
        self.assertTrue(play['tasks'][-1]['become'])
        self.assertEqual(play['tasks'][-1]['vars']['ansible_user'], t.USER)

    def test_evaluation_workflow_requires_flag_and_branch(self):
        after = yaml.safe_load((ROOT / '.circleci/config.yml').read_text())
        self.assertFalse(after['parameters']['run_p1_env_probe']['default'])
        workflow = after['workflows']['p1-environment-measurement']
        self.assertEqual(workflow['jobs'], ['p1-environment'])
        self.assertEqual(workflow['when']['and'], [
            '<< pipeline.parameters.run_p1_env_probe >>',
            {'equal': [h.BRANCH, '<< pipeline.git.branch >>']}])

    def mocked_main(self, runtime=None, cleanup_ok=True, manifest_fail=False, controller_rc=0):
        runtime = valid_report() if runtime is None else runtime
        inventory = SimpleNamespace(now=lambda: '2026-11-14T00:00:00Z')

        def registry(ref, info, end):
            if manifest_fail:
                raise RuntimeError('SECRET')
            return {'platform_manifest_digest': h.CONTROLLER.split('@')[1] if ref == h.CONTROLLER else h.TARGET_MANIFEST,
                    'config_digest': h.CONTROLLER_CONFIG if ref == h.CONTROLLER else h.TARGET_CONFIG}

        inventory.registry_identity = registry

        def command(argv, *args, **kwargs):
            if '/p1/runtime_controller.py' in argv:
                mount = next(x for x in argv if x.startswith('type=bind,src=/tmp/ruby-p1-r11-'))
                directory = Path(mount.split('src=', 1)[1].split(',dst=', 1)[0])
                self.assertEqual([x.name for x in (directory / 'callback_plugins').iterdir()], ['runtime_callback.py'])
                return controller_rc, json.dumps(runtime)
            return 'abc123'

        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict(h.os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': h.BRANCH}), \
                patch.object(h.platform, 'system', return_value='Linux'), \
                patch.object(h.platform, 'machine', return_value='x86_64'), \
                patch.object(h.os, 'stat', wraps=os.stat) as os_stat, \
                patch.object(h, 'load', side_effect=lambda n: inventory if n == 'env_probe' else p), \
                patch.object(h, 'command', side_effect=command) as commands, \
                patch.object(h, 'inspect_image', return_value={}), \
                patch.object(h, 'cleanup', return_value=cleanup_ok) as cleanup, \
                contextlib.redirect_stdout(io.StringIO()):
            real_stat = os_stat._mock_wraps
            os_stat.side_effect = lambda path, *a, **kw: (SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=0, st_gid=123)
                if str(path) == '/var/run/docker.sock' else real_stat(path, *a, **kw))
            path = Path(tmp) / 'result.json'
            result = h.main(['--output', str(path), '--allow-pull', '--ephemeral-ci',
                             '--allow-ci-docker-api', '--allow-disposable-sudo-fixture'])
            return result, json.loads(path.read_text()), cleanup.call_count, commands.call_count

    def test_success_keeps_phase_and_production_claims_false(self):
        rc, result, clean_count, _ = self.mocked_main()
        self.assertEqual(rc, 0)
        self.assertTrue(result['fixture_become_verified'])
        for key in ('p1_02_complete', 'phase1_complete', 'production_become_verified',
                    'production_mounts_verified', 'repository_access_verified',
                    'dependency_resolution_verified', 'stock_sudo_nonroot_verified'):
            self.assertIs(result[key], False)
        self.assertEqual(clean_count, 2)
        self.assertTrue(result['cleanup_confirmed'])

    def test_failed_runtime_preserves_only_safe_diagnostics_and_cleans_both(self):
        value = {'status': 'INCOMPLETE', 'stage': 'ansible_playbook', 'reason': 'SECRET',
                 'command': {'returncode': 2, 'stdout_bytes': 200, 'stderr_bytes': 30}}
        rc, result, clean_count, _ = self.mocked_main(value)
        self.assertEqual(rc, 3)
        self.assertEqual(clean_count, 2)
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertEqual(result['runtime_attempt']['command']['returncode'], 2)
        self.assertFalse(result['fixture_become_verified'])

    def test_cleanup_failure_prevents_overall_success(self):
        rc, result, _, _ = self.mocked_main(cleanup_ok=False)
        self.assertEqual(rc, 3)
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(result['reason'], 'CLEANUP_UNCONFIRMED')

    def test_success_payload_with_nonzero_exit_does_not_pass(self):
        rc, result, clean_count, _ = self.mocked_main(controller_rc=3)
        self.assertEqual(rc, 3)
        self.assertEqual(clean_count, 2)
        self.assertEqual(result['reason'], 'CONTROLLER_EXIT_STATUS_MISMATCH')

    def test_registry_mismatch_prevents_target_and_fixture_creation(self):
        rc, result, clean_count, command_count = self.mocked_main(manifest_fail=True)
        self.assertEqual(rc, 3)
        self.assertEqual(clean_count, 0)
        self.assertEqual(command_count, 1)
        self.assertNotIn('SECRET', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
