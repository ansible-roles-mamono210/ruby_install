"""Offline checks for fixed-plan installation and Rust smoke evidence."""
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
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


h = module('r34_host_test', ROOT / 'scripts/p1/rust_install_probe.py')
w = h.load('rust_install_container_probe')
i = h.load('install_container_probe')
d = h.profile(h.load('dependency_container_probe'))
dh = h.load('dependency_probe')
b = module('r34_base_fixture', ROOT / 'tests/test_install_probe.py')
PLAN = json.loads(h.verified_text('ci430_dependency_plan.json'))
FLAGS = ['--allow-pull', '--ephemeral-ci', '--allow-rust-install', '--allow-ci430-replacements']
VERSION = 'rustc 1.99.1 (abcdef123 2026-11-01)\nbinary: rustc\ncommit-hash: abcdef123\nhost: x86_64-unknown-linux-gnu\nrelease: 1.99.1\nLLVM version: 23.1.3\n'


def fixture():
    result = b.fixture()
    result.pop('transaction_plan_matches_ci416')
    result.update(schema=w.SCHEMA, status=w.SUCCESS, plan_reference='CI430',
        transaction_plan_matches_ci430=True, rust_installed=True, rust_compiler_checked=True,
        p1_04_complete=False, candidates_present=list(h.PACKAGES),
        plan={k: copy.deepcopy(PLAN[k]) for k in ('install_set', 'remove_set')},
        rpms=[{'package': copy.deepcopy(r), 'sha256': 'b' * 64, 'bytes': 100,
               'signature_verified': True} for r in PLAN['install_set']],
        delta={'added_or_upgraded': 35, 'replaced_old_versions': 9, 'new_package_names': 26,
               'public_keys_added': 0, 'exact_plan_match': True},
        rpm_after={'count': 189, 'sha256': 'c' * 64},
        rust_version={'release': '1.99.1', 'host': w.RUST_HOST},
        rust_smoke=[{'name': name, 'returncode': 0, 'stderr_bytes': 0, 'output_match': True,
                     'elapsed_seconds': 0.1} for name in w.RUST_NAMES])
    return result


def validate(value):
    h.validate(value, PLAN, w, i, dh, d)


class EvidenceTests(unittest.TestCase):
    def test_full_valid_rust_install_evidence(self):
        validate(fixture())

    def test_ci430_plan_has_exact_selected_rust_and_retained_replacements(self):
        self.assertEqual(len(PLAN['install_set']), 35)
        self.assertEqual(len(PLAN['remove_set']), 9)
        self.assertEqual([r for r in PLAN['install_set'] if r['name'] == 'rust'],
            [{'name': 'rust', 'epoch': '0', 'version': '1.99.1', 'release': '1.el9',
              'arch': 'x86_64', 'reponame': 'appstream'}])
        i.check_plan(PLAN['install_set'], PLAN['remove_set'], PLAN, lambda a, b: 1)

    def test_changed_signature_plan_or_completion_flags_are_rejected(self):
        for key, value in [('all_signatures_verified', False), ('rust_installed', False),
                           ('rust_compiler_checked', False), ('transaction_returned', False),
                           ('transaction_plan_matches_ci430', False), ('plan_reference', 'CI416'),
                           ('p1_04_complete', True), ('ruby_build_verified', True),
                           ('schema', i.SCHEMA), ('status', i.SUCCESS)]:
            result = fixture(); result[key] = value
            with self.subTest(key=key), self.assertRaises(h.Stop):
                validate(result)

    def test_original_plan_counts_cannot_pass(self):
        for key, value in [('added_or_upgraded', 30), ('new_package_names', 21),
                           ('replaced_old_versions', 0), ('public_keys_added', True)]:
            result = fixture(); result['delta'][key] = value
            with self.subTest(key=key), self.assertRaises(h.Stop):
                validate(result)

    def test_rpm_delta_count_includes_imported_keys(self):
        result = fixture(); result['delta']['public_keys_added'] = 1
        with self.assertRaises(h.Stop): validate(result)
        result['rpm_after']['count'] = 190
        validate(result)

    def test_missing_duplicate_wrong_origin_or_unsigned_rpm_rejected(self):
        for mode in ('missing', 'duplicate', 'origin', 'unsigned'):
            result = fixture()
            if mode == 'missing': result['rpms'].pop()
            elif mode == 'duplicate': result['rpms'][0] = result['rpms'][1]
            elif mode == 'origin': result['rpms'][0]['package']['reponame'] = 'other'
            else: result['rpms'][0]['signature_verified'] = False
            with self.subTest(mode=mode), self.assertRaises((h.Stop, dh.Stop)): validate(result)

    def test_wrong_release_host_and_extra_version_fields_rejected(self):
        for value in [{'release': '1.98.1', 'host': w.RUST_HOST},
                      {'release': '1.99.1', 'host': 'aarch64-unknown-linux-gnu'},
                      {'release': '1.99.1', 'host': w.RUST_HOST, 'raw': 'SECRET'}]:
            result = fixture(); result['rust_version'] = value
            with self.assertRaises(h.Stop): validate(result)

    def test_rust_smoke_false_exit_stderr_mismatch_and_nan_rejected(self):
        for field, value in [('returncode', False), ('returncode', 1), ('stderr_bytes', 1),
                             ('output_match', False), ('elapsed_seconds', float('nan')),
                             ('name', 'other')]:
            result = fixture(); result['rust_smoke'][1][field] = value
            with self.subTest(field=field), self.assertRaises(h.Stop): validate(result)

    def test_smoke_must_contain_all_three_checks(self):
        result = fixture(); result['rust_smoke'].pop()
        with self.assertRaises(h.Stop): validate(result)

    def test_failure_diagnostics_never_copy_arbitrary_details(self):
        value = {'schema': w.SCHEMA, 'stage': 'rust_smoke', 'reason': 'RUST_SMOKE_FAILED',
                 'rust_installed': True, 'raw': 'SECRET', 'rust_smoke': [dict(fixture()['rust_smoke'][0],
                 output_match=False, raw='SECRET')]}
        result = h.failure(value, w, i)
        self.assertTrue(result['rust_installed'])
        self.assertEqual(result['rust_smoke'][0]['output_match'], False)
        self.assertNotIn('SECRET', json.dumps(result))


class RustCompilerTests(unittest.TestCase):
    def test_verbose_version_matches_exact_release_and_host(self):
        self.assertEqual(w.parse_version(VERSION, '1.99.1'), {'release': '1.99.1', 'host': w.RUST_HOST})
        for text in ('', VERSION.replace('1.99.1', '1.99.0'),
                     VERSION.replace(w.RUST_HOST, 'other'), VERSION + 'release: 1.99.1\n'):
            with self.assertRaises(w.Stop): w.parse_version(text, '1.99.1')

    def run_smoke(self, results):
        report = {}
        with tempfile.TemporaryDirectory() as directory, patch.object(w.subprocess, 'run', side_effect=results) as run:
            w.rust_smoke(directory, PLAN, report)
        return report, run

    def results(self):
        return [SimpleNamespace(returncode=0, stdout=s, stderr='')
                for s in (VERSION, '', 'RUST_COMPILER_OK\n')]

    def test_real_compile_and_run_commands_with_clean_environment(self):
        report, run = self.run_smoke(self.results())
        self.assertTrue(report['rust_compiler_checked'])
        self.assertEqual([r['name'] for r in report['rust_smoke']], list(w.RUST_NAMES))
        args = run.call_args_list[1].args[0]
        self.assertEqual(args[:4], ['/usr/bin/rustc', '--edition=2021', '-C', 'opt-level=0'])
        for call in run.call_args_list:
            self.assertEqual(set(call.kwargs['env']), {'PATH', 'LANG', 'HOME'})
            self.assertEqual(call.kwargs['timeout'], 90)
            self.assertNotIn('shell', call.kwargs)

    def test_compile_failure_stops_before_program(self):
        values = self.results(); values[1].returncode = 1
        with tempfile.TemporaryDirectory() as directory, patch.object(w.subprocess, 'run', side_effect=values) as run:
            report = {}
            with self.assertRaisesRegex(w.Stop, 'RUST_SMOKE_FAILED'): w.rust_smoke(directory, PLAN, report)
            self.assertEqual(run.call_count, 2)
            self.assertNotIn('rust_compiler_checked', report)

    def test_bad_version_or_stderr_never_compiles(self):
        for value in [SimpleNamespace(returncode=0, stdout=VERSION.replace('1.99.1', '1.98.1'), stderr=''),
                      SimpleNamespace(returncode=0, stdout=VERSION, stderr='warning')]:
            with tempfile.TemporaryDirectory() as directory, patch.object(w.subprocess, 'run', return_value=value) as run:
                with self.assertRaises(w.Stop): w.rust_smoke(directory, PLAN, {})
                self.assertEqual(run.call_count, 1)

    def test_wrong_program_output_cannot_pass(self):
        values = self.results(); values[2].stdout = 'wrong\n'
        with self.assertRaises(w.Stop): self.run_smoke(values)

    def test_installer_finishes_before_rust_and_relabels_actual_plan(self):
        report = {}; calls = []
        def installed(*args):
            calls.append('install'); args[-1].update(transaction_plan_matches_ci416=True, status=i.SUCCESS)
        installer = SimpleNamespace(execute=installed)
        def rust(*args):
            self.assertEqual(args[-1]['status'], 'INCOMPLETE'); calls.append('rust')
        with patch.object(w, 'rust_smoke', side_effect=rust):
            w.execute(installer, d, None, None, PLAN, '/unused', report)
        self.assertEqual(calls, ['install', 'rust'])
        self.assertTrue(report['transaction_plan_matches_ci430'])
        self.assertNotIn('transaction_plan_matches_ci416', report)
        self.assertEqual(report['status'], w.SUCCESS)

    def test_install_failure_never_runs_rust_and_keeps_plan_identity(self):
        def failed(*args):
            args[-1]['transaction_plan_matches_ci416'] = True
            raise i.Stop('RPM_SIGNATURE')
        report = {}
        with patch.object(w, 'rust_smoke') as rust, self.assertRaises(i.Stop):
            w.execute(SimpleNamespace(execute=failed), d, None, None, PLAN, '/unused', report)
        rust.assert_not_called()
        self.assertTrue(report['transaction_plan_matches_ci430'])
        self.assertNotIn('transaction_plan_matches_ci416', report)

    def test_rust_failure_does_not_leave_installer_success(self):
        def installed(*args): args[-1].update(status=i.SUCCESS, transaction_plan_matches_ci416=True)
        report = {}
        with patch.object(w, 'rust_smoke', side_effect=w.Stop('RUST_SMOKE_FAILED')), self.assertRaises(w.Stop):
            w.execute(SimpleNamespace(execute=installed), d, None, None, PLAN, '/unused', report)
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertTrue(report['rust_installed'])


class BoundaryTests(unittest.TestCase):
    def test_bundle_profiles_only_isolated_dependency_module(self):
        text = h.bundle(h.verified_text('ci430_dependency_plan.json'))
        ns = {'__name__': 'r34_bundle_test'}
        exec(compile(text, '<bundle>', 'exec'), ns)
        self.assertEqual(ns['_dependency'].PACKAGES, h.PACKAGES)
        self.assertNotIn('rust', b.dep.PACKAGES)
        self.assertEqual(ns['SCHEMA'], w.SCHEMA)
        self.assertEqual(ns['_expected'], PLAN)

    def test_changed_helper_and_plan_rejected(self):
        with patch.object(h.Path, 'read_bytes', return_value=b'changed'):
            for name in h.HELPERS:
                with self.subTest(name=name), self.assertRaises(h.Stop): h.verified_text(name)

    def test_old_arguments_cannot_authorize_new_install(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            h.main(['--output', '/unused', '--allow-install', '--allow-ci416-replacements'])

    def test_each_explicit_flag_is_required_before_output_or_docker(self):
        for flag in FLAGS:
            with patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': h.BRANCH}), \
                    patch.object(h.platform, 'system', return_value='Linux'), \
                    patch.object(h.platform, 'machine', return_value='x86_64'), \
                    patch.object(h.os, 'open') as output, patch.object(h, 'load') as loader, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(h.main(['--output', '/unused'] + [f for f in FLAGS if f != flag]), 3)
                output.assert_not_called(); loader.assert_not_called()

    def test_wrong_branch_stops_before_output(self):
        with patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': 'main'}), \
                patch.object(h.os, 'open') as output, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(h.main(['--output', '/unused'] + FLAGS), 3)
            output.assert_not_called()

    def test_existing_output_is_not_overwritten_and_docker_is_not_loaded(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': h.BRANCH}), \
                patch.object(h.platform, 'system', return_value='Linux'), \
                patch.object(h.platform, 'machine', return_value='x86_64'), \
                patch.object(h, 'load') as loader, contextlib.redirect_stdout(io.StringIO()):
            path = Path(directory) / 'existing.json'; path.write_text('keep')
            self.assertEqual(h.main(['--output', str(path)] + FLAGS), 3)
            self.assertEqual(path.read_text(), 'keep'); loader.assert_not_called()

    def test_container_has_no_mounts_socket_or_privileged_mode(self):
        rt = h.load('runtime_smoke'); ih = h.load('install_probe')
        args = h.arguments(rt, ih, 'test', 'id')
        for denied in ('--privileged', '-v', '--volume', '--mount', '--tmpfs', '--pid', '--network=host'):
            self.assertNotIn(denied, args)
        self.assertEqual(args[args.index('--network') + 1], 'bridge')
        self.assertEqual(args[args.index('--user') + 1], '0:0')
        self.assertEqual(args[args.index('--memory-swap') + 1], '2g')
        self.assertEqual(args[args.index('--cap-drop') + 1], 'ALL')
        self.assertEqual(args[args.index('--env') + 1], 'RUBY_P1_RUST_INSTALL_PROBE=r34')

    def test_plan_drift_stops_before_download_and_transaction(self):
        with patch.object(b, 'PLAN', PLAN):
            base, dnf, rpm, dep = b.ExecutionOrderTests().setup_base()
        dep.PACKAGES = h.PACKAGES
        base.transaction.install_set[0].version = 'changed'
        with patch.object(i, 'inventory', return_value=[]), self.assertRaisesRegex(i.Stop, 'TRANSACTION_PLAN_CHANGED'):
            w.execute(i, dep, dnf, rpm, PLAN, '/unused', {})
        base.download_packages.assert_not_called(); base.do_transaction.assert_not_called()

    def test_signature_failure_stops_before_transaction(self):
        with patch.object(b, 'PLAN', PLAN):
            base, dnf, rpm, dep = b.ExecutionOrderTests().setup_base()
        dep.PACKAGES = h.PACKAGES
        with patch.object(i, 'inventory', return_value=[]), patch.object(i, 'download_and_verify', side_effect=i.Stop('RPM_SIGNATURE')), \
                self.assertRaisesRegex(i.Stop, 'RPM_SIGNATURE'):
            w.execute(i, dep, dnf, rpm, PLAN, '/unused', {})
        base.do_transaction.assert_not_called()

    def run_host(self, value=None, rc=0, stderr='', cleanup=True, timeout=False, image=True):
        runtime = h.load('runtime_smoke'); inventory = h.load('env_probe'); original = h.load
        runtime.command = Mock(); runtime.inspect_image = Mock(); runtime.cleanup = Mock(return_value=cleanup)
        inventory.registry_identity = Mock(return_value={'platform_manifest_digest': runtime.TARGET_MANIFEST if image else 'changed',
                                                        'config_digest': runtime.TARGET_CONFIG})
        def loader(name):
            return {'runtime_smoke': runtime, 'env_probe': inventory}.get(name) or original(name)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': h.BRANCH}), \
                patch.object(h.platform, 'system', return_value='Linux'), patch.object(h.platform, 'machine', return_value='x86_64'), \
                patch.object(h, 'load', side_effect=loader), patch.object(h.os, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=0)), \
                patch.object(h.subprocess, 'run') as run, contextlib.redirect_stdout(io.StringIO()):
            if timeout: run.side_effect = subprocess.TimeoutExpired('docker', 960)
            else: run.return_value = SimpleNamespace(returncode=rc, stderr=stderr, stdout=json.dumps(value if value is not None else fixture()))
            path = Path(directory) / 'result.json'
            code = h.main(['--output', str(path)] + FLAGS)
            saved = json.loads(path.read_text())
        return code, saved, runtime, run

    def test_host_accepts_valid_evidence_and_cleans_up(self):
        code, saved, runtime, run = self.run_host()
        self.assertEqual(code, 0); self.assertEqual(saved['status'], w.SUCCESS)
        self.assertTrue(saved['rust_installed']); self.assertFalse(saved['ruby_build_verified'])
        self.assertEqual(len(saved['source_sha256']), 9)
        runtime.cleanup.assert_called_once(); run.assert_called_once()

    def test_failed_cleanup_is_not_success(self):
        code, saved, _, _ = self.run_host(cleanup=False)
        self.assertEqual(code, 3); self.assertEqual(saved['reason'], 'CLEANUP_UNCONFIRMED')

    def test_timeout_cleans_up_and_never_retries(self):
        code, saved, runtime, run = self.run_host(timeout=True)
        self.assertEqual(code, 3); self.assertEqual(saved['reason'], 'COMMAND_TIMEOUT')
        runtime.cleanup.assert_called_once(); run.assert_called_once()

    def test_nonzero_exit_stderr_or_invalid_evidence_never_pass(self):
        cases = [{'rc': 1}, {'stderr': 'SECRET'}, {'value': dict(fixture(), rust_compiler_checked=False)}]
        for case in cases:
            code, saved, runtime, run = self.run_host(**case)
            self.assertEqual(code, 3); self.assertEqual(saved['status'], 'INCOMPLETE')
            self.assertNotIn('SECRET', json.dumps(saved))
            runtime.cleanup.assert_called_once(); run.assert_called_once()

    def test_image_mismatch_never_starts_container(self):
        code, saved, runtime, run = self.run_host(image=False)
        self.assertEqual(code, 3); self.assertEqual(saved['reason'], 'REGISTRY_MISMATCH')
        run.assert_not_called(); runtime.cleanup.assert_not_called()


if __name__ == '__main__':
    unittest.main()
