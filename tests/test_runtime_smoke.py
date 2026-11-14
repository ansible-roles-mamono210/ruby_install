"""Offline boundary, protocol, and failure tests; never contacts Docker/Ansible."""
import contextlib
import builtins
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
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
with patch.dict(sys.modules, {'runtime_protocol': p}):
    c = load('runtime_controller')


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


class RuntimeDiagnosticTests(unittest.TestCase):
    def test_exception_chain_retains_only_finite_labels(self):
        raw = ('[ERROR]: Unexpected Exception, this is probably a bug.\n'
               'Traceback (most recent call last):\n'
               '  File "/SECRET/site-packages/ansible/_internal/_rpc_host.py", line 123, in SECRET\n'
               'PermissionError: [Errno 13] SECRET credentials and path\n'
               'Traceback (most recent call last):\n'
               '  File "/SECRET/site-packages/ansible/cli/__init__.py", line 42, in cli_executor\n'
               'ansible.errors.AnsibleError: SECRET\n')
        d = p.stderr_diagnostics(raw)
        self.assertEqual(d['classification'], 'MARKERS_FOUND')
        self.assertEqual(d['exception_types'], ['AnsibleError', 'PermissionError'])
        self.assertEqual(d['components'], ['ANSIBLE_CLI', 'ANSIBLE_RPC_HOST'])
        self.assertEqual(d['errno_labels'], ['EACCES'])
        self.assertTrue(d['traceback_present'])
        self.assertTrue(d['unexpected_exception_banner'])
        self.assertEqual(p.validate_diagnostics(d), d)
        for secret in ('SECRET', '/site-packages', '123', 'credentials', 'cli_executor'):
            self.assertNotIn(secret, json.dumps(d))

    def test_real_python_traceback_is_classified_without_message(self):
        import traceback
        try:
            raise TypeError('SECRET')
        except TypeError as ex:
            d = p.stderr_diagnostics(''.join(traceback.format_exception(ex)))
        self.assertEqual(d['exception_types'], ['TypeError'])
        self.assertTrue(d['traceback_present'])
        self.assertNotIn('SECRET', json.dumps(d))
        self.assertEqual(d['components'], [])

    def test_only_traceback_file_lines_create_component_labels(self):
        raw = ('SECRET mentions /ansible/plugins/loader.py\n'
               'message contains TypeError: SECRET\n'
               '  File "/p1/callback_plugins/runtime_callback.py", line 22, in SECRET\n'
               '  File "/SECRET/p1/runtime_protocol.py", line 23, in SECRET\n')
        d = p.stderr_diagnostics(raw)
        self.assertEqual(d['components'], ['PROBE_CALLBACK'])
        self.assertEqual(d['exception_types'], [])
        self.assertNotIn('SECRET', json.dumps(d))

    def test_empty_unknown_and_nontext_do_not_guess_a_cause(self):
        for raw, expected in (('', 'EMPTY'), ('SECRET unknown error', 'UNCLASSIFIED'),
                              ('OtherPrivateError: SECRET', 'UNCLASSIFIED'),
                              (None, 'INVALID_TYPE'), ({'SECRET': 'x'}, 'INVALID_TYPE')):
            with self.subTest(expected=expected):
                d = p.stderr_diagnostics(raw)
                self.assertEqual(d['classification'], expected)
                self.assertEqual(d['exception_types'], [])
                self.assertEqual(p.validate_diagnostics(d), d)
                self.assertNotIn('SECRET', json.dumps(d))

    def test_sgr_only_and_untrusted_control_characters(self):
        d = p.stderr_diagnostics('\x1b[31mTypeError: SECRET\x1b[0m\n')
        self.assertEqual(d['exception_types'], ['TypeError'])
        for raw in ('TypeError: SECRET\x00', '\x1b]52;c;SECRET\x07', 'TypeError: SECRET\x85'):
            d = p.stderr_diagnostics(raw)
            self.assertEqual(d['classification'], 'UNSUPPORTED_CONTROL')
            self.assertEqual(p.validate_diagnostics(d), d)
            self.assertNotIn('SECRET', json.dumps(d))

    def test_byte_limit_and_multibyte_limit_do_not_publish_prefix(self):
        for raw in ('TypeError: ' + 'x' * p.DIAGNOSTIC_LIMIT,
                    '\u3042' * (p.DIAGNOSTIC_LIMIT // 3 + 1)):
            d = p.stderr_diagnostics(raw)
            self.assertEqual(d['classification'], 'TOO_LARGE')
            self.assertEqual(d['exception_types'], [])
            self.assertEqual(p.validate_diagnostics(d), d)
        d = p.stderr_diagnostics('x' * p.DIAGNOSTIC_LIMIT)
        self.assertEqual(d['classification'], 'UNCLASSIFIED')

    def test_duplicate_markers_have_canonical_bounded_output(self):
        raw = ('TypeError: [Errno 30] SECRET\nAnsibleError: SECRET\n' * 10)
        d = p.stderr_diagnostics(raw)
        self.assertEqual(d['exception_types'], ['AnsibleError', 'TypeError'])
        self.assertEqual(d['errno_labels'], ['EROFS'])
        self.assertEqual(p.validate_diagnostics(d), d)
        self.assertLess(len(json.dumps(d)), 1024)

    def test_host_validator_rejects_arbitrary_payloads_and_noncanonical_labels(self):
        base = p.stderr_diagnostics('TypeError: SECRET\nAnsibleError: SECRET')
        changes = [lambda d: d.update(raw='SECRET'),
                   lambda d: d.update(schema='SECRET'),
                   lambda d: d.update(classification='SECRET'),
                   lambda d: d.update(traceback_present=1),
                   lambda d: d.update(exception_types=['SECRET']),
                   lambda d: d.update(exception_types=['TypeError', 'TypeError']),
                   lambda d: d.update(exception_types=['TypeError', 'AnsibleError']),
                   lambda d: d.update(components={'SECRET': True}),
                   lambda d: d.update(errno_labels=[13]),
                   lambda d: d.update(classification='EMPTY')]
        for change in changes:
            d = copy.deepcopy(base)
            change(d)
            with self.assertRaises((ValueError, TypeError)):
                p.validate_diagnostics(d)
        for d in (None, [], 'SECRET', {'classification': 'EMPTY'}):
            with self.assertRaises(ValueError):
                p.validate_diagnostics(d)


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


class RuntimeControllerTests(unittest.TestCase):
    """Exercise real control flow/files with fault injection, without Ansible."""

    def run_controller(self, fault=None, paths=None, scan=True, result=None):
        paths = ['/original/collections', '/usr/share/ansible/collections',
                 '/original/collections'] if paths is None else paths
        if result is None:
            result = subprocess.CompletedProcess([], 0, json.dumps(valid_report()['ansible']), '')
        real_import = builtins.__import__
        real_write = Path.write_text
        real_temporary = tempfile.TemporaryDirectory
        captured = {}
        args = h.controller_args('controller', 'target', 'run', '/tmp/dedicated', 123)
        launcher_env = dict(args[i + 1].split('=', 1) for i, arg in enumerate(args) if arg == '--env')
        launcher_env['HOME'] = '/home/circleci'

        def imported(name, globals=None, locals=None, fromlist=(), level=0):
            if name == 'ansible' and 'constants' in fromlist:
                # Regression oracle: a read-only home cannot be the import-time temp.
                self.assertEqual(os.environ['ANSIBLE_LOCAL_TEMP'], '/tmp/ruby-p1-runtime-local')
                self.assertNotIn('ANSIBLE_HOME', os.environ)
                self.assertEqual(os.environ['HOME'], '/home/circleci')
                if fault == 'constants_import':
                    raise OSError('SECRET import failure')
                captured['constants_imported'] = True
                return SimpleNamespace(constants=SimpleNamespace(
                    COLLECTIONS_PATHS=paths, COLLECTIONS_SCAN_SYS_PATH=scan))
            return real_import(name, globals, locals, fromlist, level)

        def write(path, text, *a, **kw):
            if ((fault == 'config_write' and path.name == 'ansible.cfg') or
                    (fault == 'inventory_write' and path.name == 'inventory.json')):
                raise PermissionError('SECRET file failure')
            return real_write(path, text, *a, **kw)

        @contextlib.contextmanager
        def temporary(*a, **kw):
            if fault == 'workspace_create':
                raise OSError('SECRET temporary directory failure')
            with real_temporary(*a, **kw) as value:
                yield value
                if fault == 'workspace_cleanup':
                    raise OSError('SECRET cleanup failure')

        def execute(argv, **kw):
            captured['env'] = kw['env'].copy()
            captured['config'] = Path(kw['env']['ANSIBLE_CONFIG']).read_text()
            captured['inventory'] = json.loads(Path(argv[2]).read_text())
            self.assertEqual(kw['timeout'], 180)
            if fault == 'playbook_execute':
                raise subprocess.TimeoutExpired(argv, 180, output='SECRET')
            return result

        with real_temporary() as manifest_root:
            manifest = Path(manifest_root) / 'community/docker/MANIFEST.json'
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({'collection_info': {'version':
                                '0.0.0' if fault == 'collection_manifest' else '5.4.0'}}))
            with patch.object(c, 'COLLECTION_ROOT', manifest_root), \
                    patch.object(c.sys, 'argv', ['runtime_controller.py', 'ruby-p1-' + 'a' * 32 + '-runtime-target']), \
                    patch.object(c.os, 'getuid', return_value=0 if fault == 'controller_identity' else 1000), \
                    patch.object(c.platform, 'python_version', return_value='3.14.10'), \
                    patch.object(c.importlib.metadata, 'version', return_value='2.21.6'), \
                    patch.dict(c.os.environ, launcher_env, clear=True), \
                    patch.object(builtins, '__import__', side_effect=imported), \
                    patch.object(c.Path, 'write_text', new=write), \
                    patch.object(c.tempfile, 'TemporaryDirectory', side_effect=temporary), \
                    patch.object(c.shutil, 'which', return_value=None if fault == 'playbook_lookup' else '/fixed/ansible-playbook'), \
                    patch.object(c.subprocess, 'run', side_effect=execute) as run, \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                before = dict(os.environ)
                rc = c.main()
                self.assertEqual(dict(os.environ), before)
            output = out.getvalue()
            self.assertNotIn('SECRET', output)
            return rc, json.loads(output), run.call_count, captured

    def test_import_has_writable_temp_and_child_preserves_search_settings(self):
        rc, report, calls, captured = self.run_controller(scan=False)
        self.assertEqual((rc, calls), (0, 1))
        p.validate_report(report)
        self.assertNotIn('checkpoint', report)
        self.assertTrue(captured['constants_imported'])
        self.assertEqual(captured['env']['ANSIBLE_COLLECTIONS_PATH'],
                         '/original/collections:/usr/share/ansible/collections:/original/collections')
        self.assertEqual(captured['env']['ANSIBLE_COLLECTIONS_SCAN_SYS_PATH'], 'false')
        self.assertEqual(captured['env']['ANSIBLE_HOME'], '/tmp/ruby-p1-runtime-home')
        self.assertEqual(captured['env']['ANSIBLE_LOCAL_TEMP'], '/tmp/ruby-p1-runtime-local')

    def test_missing_launcher_temp_reproduces_preflight_stop_in_stub(self):
        args = h.controller_args('controller', 'target', 'run', '/tmp/dedicated', 123)
        index = args.index('ANSIBLE_LOCAL_TEMP=/tmp/ruby-p1-runtime-local')
        del args[index - 1:index + 1]
        with patch.object(h, 'controller_args', return_value=args):
            rc, report, calls, _ = self.run_controller()
        self.assertEqual((rc, calls), (3, 0))
        self.assertEqual(report['checkpoint'], 'constants_import')

    def test_preflight_faults_stop_before_playbook_and_identify_checkpoint(self):
        for fault in ('controller_identity', 'collection_manifest', 'constants_import',
                      'workspace_create', 'config_write', 'inventory_write', 'playbook_lookup'):
            with self.subTest(fault=fault):
                rc, report, calls, _ = self.run_controller(fault=fault)
                self.assertEqual((rc, calls), (3, 0))
                self.assertEqual(report['stage'], 'preflight')
                self.assertEqual(report['checkpoint'], fault)
                self.assertEqual(report['reason'], 'RUNTIME_UNCONFIRMED')

    def test_invalid_search_paths_do_not_fall_back_or_start_playbook(self):
        for paths, scan in (([], True), (['relative'], True), (['/a:/b'], True),
                            (['/a\nSECRET'], True), (['/valid'], 'true')):
            with self.subTest(paths=paths, scan=scan):
                rc, report, calls, _ = self.run_controller(paths=paths, scan=scan)
                self.assertEqual((rc, calls), (3, 0))
                self.assertEqual(report['checkpoint'], 'collection_settings')

    def test_playbook_failure_or_warning_is_not_accepted(self):
        for result in (subprocess.CompletedProcess([], 2, 'SECRET', ''),
                       subprocess.CompletedProcess([], 0, 'SECRET', 'warning SECRET')):
            rc, report, calls, _ = self.run_controller(result=result)
            self.assertEqual((rc, calls), (3, 1))
            self.assertEqual(report['checkpoint'], 'playbook_result')

    def test_exit_250_publishes_markers_and_never_raw_stderr(self):
        rc, report, calls, _ = self.run_controller(result=subprocess.CompletedProcess(
            [], 250, '', 'Traceback (most recent call last):\nTypeError: SECRET\n'))
        self.assertEqual((rc, calls), (3, 1))
        self.assertEqual(report['command']['returncode'], 250)
        self.assertEqual(report['checkpoint'], 'playbook_result')
        self.assertEqual(report['diagnostics']['exception_types'], ['TypeError'])
        p.validate_diagnostics(report['diagnostics'])

    def test_marker_matching_does_not_allow_warning_success(self):
        result = subprocess.CompletedProcess([], 0, json.dumps(valid_report()['ansible']),
                                             'TypeError: SECRET warning-like text')
        rc, report, calls, _ = self.run_controller(result=result)
        self.assertEqual((rc, calls), (3, 1))
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertNotIn('ansible', report)

    def test_timeout_has_no_raw_command_output(self):
        rc, report, calls, _ = self.run_controller(fault='playbook_execute')
        self.assertEqual((rc, calls), (3, 1))
        self.assertEqual(report['checkpoint'], 'playbook_execute')
        self.assertNotIn('command', report)

    def test_callback_decode_and_schema_failures_are_distinct(self):
        for stdout, checkpoint in (('SECRET', 'callback_decode'),
                                   ('{"status":"SECRET"}', 'callback_schema')):
            rc, report, calls, _ = self.run_controller(result=subprocess.CompletedProcess([], 0, stdout, ''))
            self.assertEqual((rc, calls), (3, 1))
            self.assertEqual(report['checkpoint'], checkpoint)

    def test_temporary_cleanup_failure_cannot_leave_passed_status(self):
        rc, report, calls, _ = self.run_controller(fault='workspace_cleanup')
        self.assertEqual((rc, calls), (3, 1))
        self.assertEqual(report['checkpoint'], 'workspace_cleanup')
        self.assertEqual(report['status'], 'INCOMPLETE')


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

    def test_failure_diagnostics_survive_host_boundary_without_promoting_status(self):
        d = p.stderr_diagnostics('PermissionError: [Errno 13] SECRET')
        value = {'status': 'INCOMPLETE', 'stage': 'ansible_playbook',
                 'checkpoint': 'playbook_result', 'diagnostics': d,
                 'command': {'returncode': 250, 'stdout_bytes': 0, 'stderr_bytes': 2671}}
        rc, result, cleans, _ = self.mocked_main(value, controller_rc=3)
        self.assertEqual((rc, cleans), (3, 2))
        self.assertEqual(result['runtime_attempt']['diagnostics'], d)
        self.assertEqual(result['reason'], 'CONTROLLER_RUNTIME_UNCONFIRMED')
        self.assertFalse(result['fixture_become_verified'])
        self.assertFalse(result['phase1_complete'])

    def test_invalid_diagnostics_are_rejected_and_cleanup_still_runs(self):
        for d in ({'raw_stderr': 'SECRET'}, ['SECRET'], None,
                  dict(p.stderr_diagnostics(''), exception_types=['SECRET'])):
            value = {'status': 'INCOMPLETE', 'stage': 'ansible_playbook',
                     'checkpoint': 'playbook_result', 'diagnostics': d}
            rc, result, cleans, _ = self.mocked_main(value, controller_rc=3)
            self.assertEqual((rc, cleans), (3, 2))
            self.assertTrue(result['runtime_attempt']['diagnostics_rejected'])
            self.assertNotIn('diagnostics', result['runtime_attempt'])
            self.assertNotIn('SECRET', json.dumps(result))
            self.assertTrue(result['cleanup_confirmed'])

    def test_checkpoint_is_allowlisted_and_never_promotes_incomplete(self):
        for checkpoint in ('controller_identity', 'collection_manifest', 'constants_import',
                           'collection_settings', 'environment_copy', 'workspace_create',
                           'config_write', 'inventory_write', 'playbook_lookup',
                           'playbook_execute', 'playbook_result', 'callback_decode',
                           'callback_schema', 'workspace_cleanup', 'SECRET', ['SECRET'], None):
            value = {'status': 'INCOMPLETE', 'stage': 'preflight', 'checkpoint': checkpoint,
                     'reason': 'SECRET', 'unexpected': 'SECRET'}
            with self.subTest(checkpoint=checkpoint):
                rc, result, clean_count, _ = self.mocked_main(value, controller_rc=3)
                self.assertEqual((rc, clean_count), (3, 2))
                self.assertNotIn('SECRET', json.dumps(result))
                self.assertFalse(result['fixture_become_verified'])
                if isinstance(checkpoint, str) and checkpoint != 'SECRET':
                    self.assertEqual(result['runtime_attempt']['checkpoint'], checkpoint)
                else:
                    self.assertNotIn('checkpoint', result['runtime_attempt'])

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
