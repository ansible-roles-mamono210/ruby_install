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
    spec = importlib.util.spec_from_file_location('test_r43_' + name, ROOT / 'scripts/p1' / (name + '.py'))
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
    diagnostic = {'checkpoint': 'finished', 'source_kind': 'regular', 'source_is_file': True,
                  'source_size_bytes': w.FIXTURE_BYTES, 'source_bytes_read': w.FIXTURE_BYTES,
                  'elf64_le': True, 'x86_64': True}
    diagnostic.update({'errno': 13, 'preflight_reason': 'WORKSPACE_NOEXEC'} if noexec
                      else {'returncode': 0, 'stdout_bytes': 0, 'stderr_bytes': 0})
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
                          'binary_sha256': w.FIXTURE_SHA256, 'binary_bytes': w.FIXTURE_BYTES, 'fixture_removed': True},
            'fixture_directory_empty': True, 'mount_table_unchanged': True, 'elapsed_seconds': 0.5,
            'diagnostic': diagnostic}


def failure_fixture(reason='EXEC_FIXTURE_SOURCE', checkpoint='source_lstat'):
    row = {key: value for key, value in fixture('exec').items() if key not in (
        'execution', 'fixture_directory_empty', 'mount_table_unchanged')}
    row.update(status='INCOMPLETE', stage='kernel_execution', reason=reason,
               diagnostic={'checkpoint': checkpoint, 'exception_type': 'Stop',
                           'source_kind': 'symlink', 'source_size_bytes': 20, 'source_is_file': True})
    return row


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
            result = w.execute_fixture(temp, w.elf_bytes(Path('/usr/bin/true')), False)
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

    def test_actual_image_true_wrapper_is_rejected_before_execution(self):
        # Exact 51 bytes observed in the pinned image; this is not an ELF fixture.
        wrapper = b'#!/usr/bin/coreutils --coreutils-prog-shebang=true\n'
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'true'; source.write_bytes(wrapper)
            diagnostic = {}
            with patch.object(w, 'FIXTURE_PATH', source), patch.object(w.subprocess, 'run') as run:
                with self.assertRaisesRegex(w.Stop, '^EXEC_FIXTURE_ELF$'):
                    w.fixture_bytes(diagnostic)
                run.assert_not_called()
            self.assertEqual(diagnostic['source_bytes_read'], 51)
            self.assertEqual(diagnostic['checkpoint'], 'source_elf')

    def test_synthetic_elf_at_measured_coreutils_size_passes_bounded_read(self):
        # Only the format/size reader is tested here; actual image bytes are checked separately.
        data = b'\x7fELF\x02\x01' + b'\0' * 12 + b'\x3e\x00' + b'\0' * (1347176 - 20)
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'coreutils'; source.write_bytes(data)
            self.assertGreater(len(data), 1024 ** 2)
            self.assertEqual(w.elf_bytes(source), data)

    def test_fixture_rejects_changed_hash_and_size_even_for_valid_elf(self):
        data = b'\x7fELF\x02\x01' + b'\0' * 12 + b'\x3e\x00' + b'\0' * (1347176 - 20)
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'coreutils'
            for candidate in (data, data[:-1]):
                source.write_bytes(candidate); diagnostic = {}
                with patch.object(w, 'FIXTURE_PATH', source):
                    with self.assertRaisesRegex(w.Stop, '^EXEC_FIXTURE_IDENTITY$'):
                        w.fixture_bytes(diagnostic)
                self.assertEqual(diagnostic['checkpoint'], 'source_identity')

    def test_oversize_elf_is_read_only_to_the_finite_limit(self):
        data = b'\x7fELF\x02\x01' + b'\0' * 12 + b'\x3e\x00' + b'\0' * (3 * 1024 ** 2)
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'coreutils'; source.write_bytes(data); diagnostic = {}
            with self.assertRaisesRegex(w.Stop, '^EXEC_FIXTURE_ELF$'):
                w.elf_bytes(source, diagnostic)
            self.assertEqual(diagnostic['source_bytes_read'], 2 * 1024 ** 2 + 1)

    def test_symlink_rejection_preserves_kind_without_target_or_content(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'PRIVATE-TARGET'; source.write_bytes(b'PRIVATE-CONTENT')
            link = Path(temp) / 'true'; link.symlink_to(source)
            diagnostic = {}
            with self.assertRaisesRegex(w.Stop, '^EXEC_FIXTURE_SOURCE$'):
                w.elf_bytes(link, diagnostic)
            self.assertEqual(diagnostic['source_kind'], 'symlink')
            self.assertTrue(diagnostic['source_is_file'])
            self.assertEqual(diagnostic['checkpoint'], 'source_lstat')
            self.assertNotIn('source_bytes_read', diagnostic)
            self.assertNotIn('PRIVATE', json.dumps(diagnostic))

    def test_missing_and_invalid_elf_have_distinct_diagnostics(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'true'; diagnostic = {}
            with self.assertRaisesRegex(w.Stop, 'EXEC_FIXTURE_SOURCE'): w.elf_bytes(p, diagnostic)
            self.assertEqual(diagnostic['source_kind'], 'missing')
            p.write_bytes(b'bad ELF'); diagnostic = {}
            with self.assertRaisesRegex(w.Stop, 'EXEC_FIXTURE_ELF'): w.elf_bytes(p, diagnostic)
            self.assertEqual(diagnostic['source_bytes_read'], 7)
            self.assertFalse(diagnostic['elf64_le'])
            self.assertEqual(diagnostic['checkpoint'], 'source_elf')

    def test_unexpected_returncode_and_errno_are_kept_without_raw_output(self):
        with tempfile.TemporaryDirectory() as temp:
            diagnostic = {}
            value = SimpleNamespace(returncode=17, stdout=b'PRIVATE-STDOUT', stderr=b'PRIVATE-STDERR')
            with patch.object(w.subprocess, 'run', return_value=value):
                with self.assertRaisesRegex(w.Stop, 'EXEC_RESULT_UNEXPECTED'):
                    w.execute_fixture(temp, b'fixed', False, diagnostic)
            self.assertEqual(diagnostic['returncode'], 17)
            self.assertEqual(diagnostic['checkpoint'], 'fixture_execute')
            self.assertNotIn('PRIVATE', json.dumps(diagnostic))
            with patch.object(w.subprocess, 'run', side_effect=OSError(errno.ENOEXEC, 'PRIVATE')):
                with self.assertRaisesRegex(w.Stop, 'EXEC_ERROR_UNEXPECTED'):
                    w.execute_fixture(temp, b'fixed', False, diagnostic)
            self.assertEqual(diagnostic['errno'], errno.ENOEXEC)
            self.assertEqual(list(Path(temp).iterdir()), [])


class HostTests(unittest.TestCase):
    def test_worker_main_failure_json_survives_host_transport(self):
        # Exercise the worker's real serialization with mocked container prerequisites.
        # This does not assert that the pinned CI image contains a symlink.
        with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
            source = Path(temp) / 'PRIVATE'; source.write_bytes(b'PRIVATE')
            link = Path(temp) / 'true'; link.symlink_to(source)
            read_elf = w.elf_bytes
            stack.enter_context(patch.object(w, 'identity', return_value='exec'))
            stack.enter_context(patch.object(w.platform, 'machine', return_value='x86_64'))
            stack.enter_context(patch.object(w.platform, 'python_version', return_value='3.9.19'))
            stack.enter_context(patch.object(w.Path, 'read_text', return_value='fixed mount table'))
            stack.enter_context(patch.object(b, 'mount_for', return_value={
                'mount_point': '/tmp', 'filesystem': 'tmpfs', 'options': ['rw', 'nosuid', 'nodev']}))
            stack.enter_context(patch.object(w.os, 'statvfs', return_value=SimpleNamespace(f_flag=0)))
            stack.enter_context(patch.object(w, 'snapshot', return_value={
                'sha256': 'a' * 64, 'entries': 8, 'file_bytes': 100}))
            stack.enter_context(patch.object(w, 'fixture_bytes',
                                            side_effect=lambda diagnostic: read_elf(link, diagnostic)))
            output = stack.enter_context(patch('sys.stdout', new_callable=io.StringIO))
            rc = w.main(b)
            serialized = output.getvalue()
        self.assertEqual(rc, 3)
        self.assertNotIn('PRIVATE', serialized)
        row = json.loads(serialized)
        self.assertEqual(row['reason'], 'EXEC_FIXTURE_SOURCE')
        result = SimpleNamespace(returncode=rc, stderr='', stdout=serialized)
        with patch.object(h.subprocess, 'run', return_value=result):
            with self.assertRaises(h.WorkerFailure) as raised:
                h.run_worker(t, [], '', float('inf'), 'exec')
        self.assertEqual(raised.exception.diagnostic['diagnostic']['source_kind'], 'symlink')
        self.assertEqual(raised.exception.diagnostic['diagnostic']['checkpoint'], 'source_lstat')

    def test_valid_pair_schema(self):
        for mode in h.MODES: h.validate(fixture(mode), mode)

    def test_same_unapproved_binary_in_both_cases_fails_before_noexec(self):
        rows = [fixture(mode) for mode in h.MODES]
        for row in rows: row['execution']['binary_sha256'] = 'c' * 64
        rc, saved, calls, _ = self.run_host(rows=rows)
        self.assertEqual((rc, calls), (3, 1))
        self.assertEqual(saved['reason'], 'WORKER_EXECUTION')

    def test_pinned_binary_size_and_identity_failure_transport(self):
        row = fixture('exec')
        row['execution']['binary_bytes'] -= 1
        with self.assertRaisesRegex(h.Stop, '^WORKER_EXECUTION$'):
            h.validate(row, 'exec')
        row = failure_fixture('EXEC_FIXTURE_IDENTITY', 'source_identity')
        result = h.checked_failure(row, 3, 'exec')
        self.assertEqual(result['reason'], 'EXEC_FIXTURE_IDENTITY')
        self.assertEqual(result['diagnostic']['checkpoint'], 'source_identity')

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
            with self.assertRaisesRegex(h.Stop, '^WORKER_FAILURE_SCHEMA$'):
                h.run_worker(t, [], '', float('inf'), 'exec')

    def test_worker_reason_survives_transport_without_raw_fields(self):
        row = failure_fixture(); row['exception_text'] = 'PRIVATE'; row['stdout'] = 'PRIVATE'
        result = SimpleNamespace(returncode=3, stderr='', stdout=json.dumps(row))
        with patch.object(h.subprocess, 'run', return_value=result):
            with self.assertRaises(h.WorkerFailure) as raised:
                h.run_worker(t, [], '', float('inf'), 'exec')
        data = raised.exception.diagnostic
        self.assertEqual(data['reason'], 'EXEC_FIXTURE_SOURCE')
        self.assertEqual(data['diagnostic']['source_kind'], 'symlink')
        self.assertNotIn('PRIVATE', json.dumps(data))

    def test_malformed_failure_is_never_preserved_as_evidence(self):
        for mutate in (lambda x: x.update(reason='PRIVATE'), lambda x: x.update(status=w.SUCCESS),
                       lambda x: x.update(stage=[]), lambda x: x.update(reason={}),
                       lambda x: x.update(schema='ruby-p1-noexec-container-r40'),
                       lambda x: x.update(mode='noexec'), lambda x: x.update(phase1_complete=True),
                       lambda x: x.update(elapsed_seconds=float('inf')),
                       lambda x: x['diagnostic'].update(checkpoint='finished'),
                       lambda x: x['diagnostic'].update(errno=True),
                       lambda x: x['diagnostic'].update(source_size_bytes=-1),
                       lambda x: x['diagnostic'].update(source_bytes_read=w.MAX_FIXTURE_BYTES + 2),
                       lambda x: x['diagnostic'].update(path='PRIVATE')):
            row = failure_fixture(); mutate(row)
            with self.assertRaises(h.Stop): h.checked_failure(row, 3, 'exec')

    def test_diagnostic_failure_does_not_satisfy_success_schema(self):
        with self.assertRaises(h.Stop): h.validate(failure_fixture(), 'exec')
        row = fixture('exec'); row['diagnostic']['checkpoint'] = 'source_lstat'
        with self.assertRaisesRegex(h.Stop, 'WORKER_DIAGNOSTIC_INCOMPLETE'): h.validate(row, 'exec')

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
            stack.enter_context(patch.object(h, 'load', side_effect=lambda name:
                t if name == 'target_probe' else w if name == 'noexec_container_probe' else inventory))
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
        self.assertEqual(saved['reason'], 'WORKER_EXECUTION')

    def test_host_saves_diagnostic_and_stops_before_second_case(self):
        failure = h.WorkerFailure(h.checked_failure(failure_fixture(), 3, 'exec'))
        rc, saved, calls, cleanups = self.run_host(rows=[failure])
        self.assertEqual((rc, calls, cleanups), (3, 1, 1))
        self.assertEqual(saved['reason'], 'WORKER_FAILED_KERNEL_EXECUTION')
        self.assertEqual(saved['failure_diagnostic']['reason'], 'EXEC_FIXTURE_SOURCE')
        self.assertEqual(saved['failure_diagnostic']['diagnostic']['source_kind'], 'symlink')
        self.assertEqual(saved['results'], [])
        self.assertTrue(saved['cleanup']['exec'])


if __name__ == '__main__':
    unittest.main()
