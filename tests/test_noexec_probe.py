"""Local tests of the proposal; mocked noexec is not a target CI result."""
import copy
import contextlib
import errno
import hashlib
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


def module(name):
    spec = importlib.util.spec_from_file_location('test_r40_' + name, ROOT / 'scripts/p1' / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


h = module('noexec_probe')
w = module('noexec_container_probe')
b = module('build_container_probe')
t = module('target_probe')


def fixture(mode='noexec'):
    noexec = mode == 'noexec'
    state = {'sha256': 'a' * 64, 'entries': 8, 'file_bytes': 100}
    return {'schema': w.SCHEMA, 'status': w.SUCCESS, 'stage': 'finished',
            'scope': 'fixed_tmp_mount_and_build_preflight_only', 'role_verified': False,
            'full_build_entrypoint_executed': False, 'p1_04_complete': False,
            'phase1_complete': False, 'mode': mode,
            'platform': {'os': 'centos-stream-9', 'arch': 'x86_64', 'python': '3.9.19'},
            'mount': {'path': '/tmp', 'filesystem': 'tmpfs', 'mountinfo_noexec': noexec,
                      'statvfs_noexec': noexec, 'read_only': False, 'nosuid': True, 'nodev': True},
            'preflight': {'called': noexec, 'reason': 'WORKSPACE_NOEXEC' if noexec else 'NOT_RUN_ON_EXEC_CONTROL'},
            'guard_state': {'before': state, 'after': copy.deepcopy(state), 'unchanged': True},
            'execution': {'outcome': 'EACCES' if noexec else 'EXECUTED', 'errno': 13 if noexec else None,
                          'returncode': None if noexec else 0, 'stdout_bytes': 0, 'stderr_bytes': 0,
                          'binary_sha256': 'b' * 64, 'binary_bytes': 4096, 'fixture_removed': True},
            'fixture_directory_empty': True, 'mount_table_unchanged': True, 'elapsed_seconds': 0.5}


class WorkerTests(unittest.TestCase):
    def test_guard_requires_the_exact_noexec_reason(self):
        for reason in ('IDENTITY', 'SPACE_LOW', 'WORKSPACE_PARENT'):
            with self.subTest(reason=reason), patch.object(b, 'preflight', side_effect=b.Stop(reason)):
                with self.assertRaisesRegex(w.Stop, 'PREFLIGHT_OTHER_REASON'):
                    w.check_preflight(b, True)
        with patch.object(b, 'preflight', side_effect=b.Stop('WORKSPACE_NOEXEC')):
            self.assertEqual(w.check_preflight(b, True), {'called': True, 'reason': 'WORKSPACE_NOEXEC'})

    def test_guard_cannot_report_a_successful_preflight_as_rejection(self):
        with patch.object(b, 'preflight', return_value={}):
            with self.assertRaisesRegex(w.Stop, 'PREFLIGHT_DID_NOT_REJECT'):
                w.check_preflight(b, True)

    def test_exec_control_does_not_run_build_preflight(self):
        with patch.object(b, 'preflight') as preflight:
            self.assertFalse(w.check_preflight(b, False)['called'])
            preflight.assert_not_called()

    def test_guard_snapshot_detects_config_content_mode_and_new_workspace(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); config = root / 'repo'; config.write_text('enabled=0'); config.chmod(0o644)
            before = w.snapshot((root,))
            self.assertEqual(before, w.snapshot((root,)))
            config.write_text('enabled=1')
            self.assertNotEqual(before, w.snapshot((root,)))
            before = w.snapshot((root,)); config.chmod(0o600)
            self.assertNotEqual(before, w.snapshot((root,)))
            before = w.snapshot((root,)); (root / 'unexpected-workspace').mkdir()
            self.assertNotEqual(before, w.snapshot((root,)))

    def test_snapshot_does_not_follow_symlinks_or_expose_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'self').symlink_to(root, target_is_directory=True)
            result = w.snapshot((root,))
            self.assertEqual(result['entries'], 2)
            self.assertNotIn(temp, json.dumps(result))

    def test_snapshot_limits_files_and_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'big').write_bytes(b'x' * 16)
            with patch.object(w, 'MAX_STATE_BYTES', 8):
                with self.assertRaisesRegex(w.Stop, 'STATE_BYTE_LIMIT'): w.snapshot((root,))
            with patch.object(w, 'MAX_STATE_ENTRIES', 1):
                with self.assertRaisesRegex(w.Stop, 'STATE_ENTRY_LIMIT'): w.snapshot((root,))

    def test_native_binary_executes_and_is_removed_on_local_exec_mount(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertFalse(os.statvfs(temp).f_flag & os.ST_NOEXEC)
            result = w.execute_fixture(temp, w.elf_bytes(), False)
            self.assertEqual(result['outcome'], 'EXECUTED')
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_only_eacces_is_accepted_and_fixture_is_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            for code in (errno.EACCES, errno.ENOENT, errno.ENOEXEC, errno.EPERM):
                with self.subTest(code=code), patch.object(w.subprocess, 'run', side_effect=OSError(code, 'PRIVATE')):
                    if code == errno.EACCES:
                        self.assertEqual(w.execute_fixture(temp, b'fixed', True)['errno'], 13)
                    else:
                        with self.assertRaisesRegex(w.Stop, 'EXEC_ERROR_UNEXPECTED'):
                            w.execute_fixture(temp, b'fixed', True)
                self.assertEqual(list(Path(temp).iterdir()), [])

    def test_unexpected_exec_on_noexec_fails(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(w.subprocess, 'run',
                return_value=SimpleNamespace(returncode=0, stdout=b'', stderr=b'')):
            with self.assertRaisesRegex(w.Stop, 'EXEC_RESULT_UNEXPECTED'):
                w.execute_fixture(temp, b'fixed', True)
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_script_cannot_substitute_for_elf_fixture(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'script'; path.write_text('#!/bin/sh\nexit 0\n')
            with self.assertRaisesRegex(w.Stop, 'EXEC_FIXTURE_ELF'): w.elf_bytes(path)


class HostTests(unittest.TestCase):
    def test_valid_pair_schema(self):
        for mode in h.MODES: h.validate(fixture(mode), mode)

    def test_missing_extra_or_incomplete_records_fail(self):
        for mutate in (lambda x: x.pop('execution'), lambda x: x.update(extra='PRIVATE'),
                       lambda x: x.update(status='INCOMPLETE'), lambda x: x.update(phase1_complete=True),
                       lambda x: x.update(full_build_entrypoint_executed=True),
                       lambda x: x.update(elapsed_seconds=float('nan'))):
            row = fixture(); mutate(row)
            with self.assertRaises(h.Stop): h.validate(row, 'noexec')

    def test_mount_guard_state_and_binary_failures_are_rejected(self):
        for mutate in (lambda x: x['mount'].update(statvfs_noexec=False),
                       lambda x: x['mount'].update(nosuid=1),
                       lambda x: x['preflight'].update(reason='SPACE_LOW'),
                       lambda x: x['guard_state']['after'].update(sha256='c' * 64),
                       lambda x: x['guard_state'].update(unchanged=1),
                       lambda x: x['guard_state']['before'].update(entries=True),
                       lambda x: x['execution'].update(outcome='EXECUTED'),
                       lambda x: x['execution'].update(errno=1),
                       lambda x: x['execution'].update(binary_bytes=True),
                       lambda x: x['execution'].update(fixture_removed=False),
                       lambda x: x['execution'].update(stderr_bytes=1)):
            row = fixture(); mutate(row)
            with self.assertRaises(h.Stop): h.validate(row, 'noexec')

    def test_control_and_negative_cannot_be_interchanged(self):
        with self.assertRaises(h.Stop): h.validate(fixture('exec'), 'noexec')
        with self.assertRaises(h.Stop): h.validate(fixture('noexec'), 'exec')

    def test_container_boundary_and_mount_pair(self):
        for mode in h.MODES:
            args = h.arguments(t, 'test-name', 'run-id', mode)
            for sequence in (['--network', 'none'], ['--cap-drop', 'ALL'],
                             ['--security-opt', 'no-new-privileges'], ['--memory', '512m'],
                             ['--memory-swap', '512m'], ['--user', '0:0']):
                self.assertEqual(args[args.index(sequence[0]):args.index(sequence[0]) + 2], sequence)
            self.assertIn('--read-only', args)
            self.assertIn('/tmp:rw,nosuid,nodev,' + mode + ',size=32m,mode=1777', args)
            for forbidden in ('--privileged', '--mount', '-v', '--cap-add'):
                self.assertNotIn(forbidden, args)
        with self.assertRaises(h.Stop): h.arguments(t, 'name', 'id', 'invalid')

    def test_payload_pins_the_existing_guard_and_does_not_start_a_build(self):
        text = h.payload()
        self.assertIn((h.ROOT / 'build_container_probe.py').read_text().__repr__(), text)
        compile(text, '<payload>', 'exec')
        with patch.object(h.Path, 'read_bytes', return_value=b'changed'):
            with self.assertRaisesRegex(h.Stop, 'HELPER_CHANGED'): h.payload()

    def test_worker_failure_does_not_leak_exception_text(self):
        result = SimpleNamespace(returncode=3, stderr='', stdout=json.dumps(
            {'status': 'INCOMPLETE', 'stage': 'preflight', 'reason': 'PRIVATE'}))
        with patch.object(h.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(h.Stop, '^WORKER_FAILED_PREFLIGHT$'):
                h.run_worker(t, [], '', float('inf'))

    def test_no_ci_authorization_means_no_docker_mutation(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True), \
                patch.object(h.subprocess, 'run') as command, patch('sys.stdout', new_callable=io.StringIO):
            output = Path(temp) / 'result.json'
            self.assertEqual(h.main(['--output', str(output)]), 3)
            command.assert_not_called()
            self.assertEqual(json.loads(output.read_text())['reason'], 'EXPLICIT_EPHEMERAL_CI_REQUIRED')

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp, patch('sys.stdout', new_callable=io.StringIO):
            output = Path(temp) / 'result.json'; output.write_text('keep')
            self.assertEqual(h.main(['--output', str(output)]), 3)
            self.assertEqual(output.read_text(), 'keep')

    def run_host(self, rows=None, cleanup=True):
        rows = rows if rows is not None else [fixture('exec'), fixture('noexec')]
        inventory = SimpleNamespace(now=lambda: '2026-11-17T00:00:00Z',
            registry_identity=lambda *_: {'platform_manifest_digest': t.MANIFEST, 'config_digest': t.CONFIG})
        with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': h.BRANCH,
                                                        'CIRCLE_SHA1': 'a' * 40}, clear=True))
            stack.enter_context(patch.object(h.os, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=0)))
            stack.enter_context(patch.object(h, 'load', side_effect=lambda name: t if name == 'target_probe' else inventory))
            stack.enter_context(patch.object(t, 'command', return_value=''))
            stack.enter_context(patch.object(t, 'inspect_image', return_value={}))
            clean = stack.enter_context(patch.object(t, 'cleanup', return_value=cleanup))
            worker = stack.enter_context(patch.object(h, 'run_worker', side_effect=rows))
            stack.enter_context(patch('sys.stdout', new_callable=io.StringIO))
            output = Path(temp) / 'result.json'
            rc = h.main(['--output', str(output), '--allow-pull', '--ephemeral-ci', '--allow-noexec-fixture'])
            return rc, json.loads(output.read_text()), worker.call_count, clean.call_count

    def test_host_requires_both_cases_and_cleanup(self):
        rc, saved, calls, cleanups = self.run_host()
        self.assertEqual((rc, calls, cleanups), (0, 2, 2))
        self.assertEqual(saved['status'], h.SUCCESS)
        self.assertTrue(saved['same_binary_verified'])
        self.assertFalse(saved['role_verified'])

    def test_failed_first_control_stops_before_noexec_and_cleans(self):
        rc, saved, calls, cleanups = self.run_host(rows=[h.Stop('WORKER_TIMEOUT')])
        self.assertEqual((rc, calls, cleanups), (3, 1, 1))
        self.assertEqual(saved['results'], [])
        self.assertTrue(saved['cleanup']['exec'])

    def test_failed_cleanup_blocks_next_case_and_success(self):
        rc, saved, calls, cleanups = self.run_host(cleanup=False)
        self.assertEqual((rc, calls, cleanups), (3, 1, 2))
        self.assertEqual(saved['reason'], 'CLEANUP_UNCONFIRMED')

    def test_different_binaries_cannot_pass_comparison(self):
        row = fixture(); row['execution']['binary_sha256'] = 'c' * 64
        rc, saved, calls, _ = self.run_host(rows=[fixture('exec'), row])
        self.assertEqual((rc, calls), (3, 2))
        self.assertEqual(saved['reason'], 'CONTROL_BINARY_MISMATCH')


if __name__ == '__main__':
    unittest.main()
