"""Offline Rust solver boundaries; no Docker, RPM download, installation or build."""
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


def read_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


h = read_module('rust_host', ROOT / 'scripts/p1/rust_dependency_probe.py')
b = read_module('base_fixtures', ROOT / 'tests/test_dependency_probe.py')
PLAN = json.loads(h.verified_text('ci416_dependency_plan.json'))
FLAGS = ['--allow-pull', '--ephemeral-ci', '--allow-repo-metadata', '--allow-rust-solver']


def fixture():
    with patch.object(b.w, 'PACKAGES', h.PACKAGES):
        value = b.report()
    value.update(schema=h.SCHEMA, status=h.SUCCESS,
                 rpm_before_after=copy.deepcopy(PLAN['baseline_rpm']),
                 configuration_before_after=copy.deepcopy(PLAN['baseline_configuration']))
    selected = value['conditions'][1]['candidates'][-1]['available'][0]
    value['conditions'][1]['install_set'].append(copy.deepcopy(selected))
    return value


class RustSolverTests(unittest.TestCase):
    def setUp(self):
        self.worker = h.profile(h.load('dependency_container_probe'))
        self.host = h.load('dependency_probe')

    def test_bundle_and_host_use_same_profile_without_changing_existing_module(self):
        namespace = {}
        script = h.bundle()
        exec(script[:script.rindex('raise SystemExit')], namespace)
        worker = namespace['_worker']
        for key in ('SCHEMA', 'SUCCESS', 'PACKAGES'):
            self.assertEqual(getattr(worker, key), getattr(self.worker, key))
        self.assertNotIn('rust', b.w.PACKAGES)
        self.assertEqual(b.w.SCHEMA, 'ruby-p1-dependency-container-r26')

    def test_changed_dependency_profile_is_rejected(self):
        with self.assertRaisesRegex(h.Stop, 'DEPENDENCY_PROFILE_CHANGED'):
            h.profile(self.worker)

    def test_changed_helper_is_rejected(self):
        with patch.object(h.Path, 'read_bytes', return_value=b'changed'):
            with self.assertRaisesRegex(h.Stop, 'HELPER_CHANGED'):
                h.load('dependency_container_probe')

    def test_solver_marks_rust_but_never_downloads_or_executes_transactions(self):
        with patch.object(b, 'w', self.worker):
            base = b.Base()
            result = b.measured_condition(True, base)
        self.assertEqual(result['resolution'], 'RESOLVED')
        self.assertEqual([c.args[0] for c in base.install.call_args_list], list(h.PACKAGES))
        base.resolve.assert_called_once_with(allow_erasing=False)
        base.do_transaction.assert_not_called()
        base.download_packages.assert_not_called()
        base.init_plugins.assert_not_called()

    def test_fixed_baseline_and_rust_candidate_are_required(self):
        h.validate(fixture(), self.host, self.worker, PLAN)
        for field in ('rpm_before_after', 'configuration_before_after'):
            row = fixture()
            row[field]['sha256'] = '0' * 64
            with self.subTest(field=field), self.assertRaisesRegex(h.Stop, 'BASELINE_CHANGED'):
                h.validate(row, self.host, self.worker, PLAN)

    def test_missing_wrong_arch_or_unlisted_rust_selection_is_rejected(self):
        for mode in ('missing', 'noarch', 'unlisted'):
            row = fixture()
            selected = row['conditions'][1]['install_set']
            if mode == 'missing':
                selected.pop()
            elif mode == 'noarch':
                selected[-1]['arch'] = 'noarch'
            else:
                selected[-1]['version'] = '9.9.9'
            with self.subTest(mode=mode), self.assertRaisesRegex(h.Stop, 'RUST_PLAN_MISMATCH'):
                h.validate(row, self.host, self.worker, PLAN)

    def test_preinstalled_rust_is_rejected(self):
        row = fixture()
        rust = row['conditions'][1]['candidates'][-1]
        rust['installed'] = [dict(rust['available'][0], reponame='@System')]
        with self.assertRaisesRegex(h.Stop, 'RUST_ALREADY_INSTALLED'):
            h.validate(row, self.host, self.worker, PLAN)

    def test_duplicate_plan_is_rejected(self):
        row = fixture()
        row['conditions'][1]['install_set'].append(row['conditions'][1]['install_set'][0])
        with self.assertRaisesRegex(h.Stop, 'DUPLICATE_PLAN_ENTRY'):
            h.validate(row, self.host, self.worker, PLAN)

    def test_installation_build_or_wrong_schema_cannot_pass(self):
        for field, value in (('rpm_downloaded', True), ('transaction_executed', True),
                             ('build_verified', True), ('system_state_unchanged', False),
                             ('schema', b.w.SCHEMA), ('status', b.w.SUCCESS)):
            row = fixture()
            row[field] = value
            with self.subTest(field=field), self.assertRaises(self.host.Stop):
                h.validate(row, self.host, self.worker, PLAN)

    def test_comparison_keeps_added_removed_and_unchanged_entries(self):
        row = fixture()
        current = row['conditions'][1]
        base = {'install_set': [current['install_set'][0]], 'remove_set': [PLAN['remove_set'][0]]}
        result = h.comparison(row, base)
        self.assertEqual(result['install_set']['unchanged_count'], 1)
        self.assertEqual(result['install_set']['new_entries'], [current['install_set'][-1]])
        self.assertEqual(result['remove_set']['no_longer_planned'], base['remove_set'])
        self.assertTrue(result['changes_may_include_repository_drift'])

    def test_missing_authorization_stops_before_output_or_docker(self):
        for omitted in FLAGS:
            with patch.object(h.os, 'open') as output, patch.object(h, 'load') as load, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(h.main(['--output', '/unused'] + [f for f in FLAGS if f != omitted]), 3)
                output.assert_not_called()
                load.assert_not_called()

    def test_installation_or_previous_solver_flags_are_rejected(self):
        for flag in ('--allow-install', '--allow-solver'):
            with patch.object(h.os, 'open') as output, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    h.main(['--output', '/unused'] + FLAGS + [flag])
                output.assert_not_called()

    def run_host(self, value=None, rc=0, stderr='', cleanup=True, timeout=False,
                 manifest=True, stdout=None):
        runtime = h.load('runtime_smoke')
        rt = SimpleNamespace(**{k: getattr(runtime, k) for k in
                                ('DOCKER', 'TARGET', 'TARGET_CONFIG', 'TARGET_MANIFEST')})
        rt.command, rt.inspect_image = Mock(return_value=''), Mock(return_value={})
        rt.cleanup = Mock(return_value=cleanup)
        inv = SimpleNamespace(now=lambda: '2026-11-16T00:00:00Z', registry_identity=lambda *a: {
            'platform_manifest_digest': rt.TARGET_MANIFEST if manifest else 'wrong',
            'config_digest': rt.TARGET_CONFIG})
        modules = {'runtime_smoke': rt, 'env_probe': inv, 'dependency_probe': self.host,
                   'dependency_container_probe': h.load('dependency_container_probe')}
        proc = SimpleNamespace(returncode=rc, stdout=json.dumps(fixture() if value is None else value)
                               if stdout is None else stdout, stderr=stderr)
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': h.BRANCH}, clear=True), \
                patch.object(h.platform, 'system', return_value='Linux'), \
                patch.object(h.platform, 'machine', return_value='x86_64'), \
                patch.object(h, 'load', side_effect=modules.__getitem__), \
                patch.object(h.os, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=0)), \
                patch.object(h.subprocess, 'run', return_value=proc,
                             side_effect=subprocess.TimeoutExpired('mock', 1) if timeout else None) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            path = Path(directory) / 'result.json'
            result = h.main(['--output', str(path)] + FLAGS)
            saved = json.loads(path.read_text())
        return result, saved, rt, run

    def test_success_does_not_claim_installation_or_build_completion(self):
        rc, saved, rt, run = self.run_host()
        self.assertEqual((rc, saved['status']), (0, h.SUCCESS))
        self.assertTrue(saved['cleanup_confirmed'])
        for key in ('rust_installed', 'ruby_build_verified', 'p1_04_complete', 'phase1_complete'):
            self.assertIs(saved[key], False)
        rt.cleanup.assert_called_once()
        args = run.call_args.args[0]
        for value in ('--read-only', '--cap-drop', '65534:65534', '--pids-limit', 'no-new-privileges'):
            self.assertIn(value, args)
        for value in ('--mount', '-v', '--privileged', '--publish'):
            self.assertNotIn(value, args)

    def test_registry_mismatch_stops_before_container(self):
        rc, saved, rt, run = self.run_host(manifest=False)
        self.assertEqual((rc, saved['reason']), (3, 'REGISTRY_MISMATCH'))
        run.assert_not_called()
        rt.cleanup.assert_not_called()

    def test_cleanup_timeout_stderr_exit_malformed_json_cannot_pass(self):
        for options in ({'cleanup': False}, {'timeout': True}, {'stderr': 'SECRET'},
                        {'rc': 7}, {'stdout': 'SECRET'}, {'stdout': 'x' * 262145}):
            with self.subTest(options=list(options)):
                rc, saved, rt, run = self.run_host(**options)
                self.assertEqual((rc, saved['status']), (3, 'INCOMPLETE'))
                self.assertNotIn('SECRET', json.dumps(saved))
                rt.cleanup.assert_called_once()

    def test_unresolved_crb_on_does_not_become_success(self):
        row = fixture()
        row['conditions'][1].update(resolution='DEPSOLVE_FAILED', install_set=[], remove_set=[])
        row['crb_on_resolved'] = False
        rc, saved, rt, run = self.run_host(value=row)
        self.assertEqual((rc, saved['reason']), (3, 'CRB_ON_NOT_RESOLVED'))
        self.assertIn('measurement', saved)


if __name__ == '__main__':
    unittest.main()
