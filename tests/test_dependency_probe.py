"""Offline DNF boundary tests; the DNF API itself is verified only in the planned CI."""
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

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/p1' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


w, h, runtime = load('dependency_container_probe'), load('dependency_probe'), load('runtime_smoke')


def pkg(name='gcc', repo='baseos'):
    return SimpleNamespace(name=name, epoch=0, version='1.2.3', release='1.el9', arch='x86_64', reponame=repo)


def configuration(**changes):
    result = SimpleNamespace(read=Mock(), sslverify=True, gpgcheck=True, proxy='',
                             baseurl=[], metalink='', mirrorlist='')
    for key, value in changes.items():
        setattr(result, key, value)
    return result


class Repo:
    def __init__(self, name):
        self.__dict__.update(vars(configuration()))
        self.id, self.enabled = name, name != 'crb'
        self.metalink = 'https://mirrors.centos.org/metalink?repo=' + name

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False


class Query:
    def __init__(self, values):
        self.values = values

    def installed(self):
        return Query([p for p in self.values if p.reponame == '@System'])

    def available(self):
        return Query([p for p in self.values if p.reponame != '@System'])

    def filter(self, **filters):
        return [p for p in self.values if all(getattr(p, k) in v if type(v) is list else getattr(p, k) == v
                                            for k, v in filters.items())]


class MarkingError(Exception):
    pass


class DepsolveError(Exception):
    pass


class Base:
    def __init__(self):
        self.conf = configuration()
        self.repos = {name: Repo(name) for name in (*w.REPOS, 'extras-common')}
        self.read_all_repos = Mock()
        self.install = Mock()
        self.resolve = Mock(return_value=True)
        self.do_transaction = Mock(side_effect=AssertionError('Transaction execution forbidden'))
        self.download_packages = Mock(side_effect=AssertionError('RPM download forbidden'))
        self.init_plugins = Mock(side_effect=AssertionError('Plugins forbidden'))
        self.transaction = SimpleNamespace(install_set=[pkg()], remove_set=[])

    def fill_sack(self, **kwargs):
        assert kwargs == {'load_system_repo': True, 'load_available_repos': True}
        assert not self.conf.plugins
        assert not self.repos['extras-common'].enabled
        values = [pkg(name, 'crb' if name == 'libyaml-devel' else 'baseos') for name in w.PACKAGES]
        self.sack = SimpleNamespace(query=lambda: Query([p for p in values if self.repos[p.reponame].enabled]))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def fake_dnf(base):
    return SimpleNamespace(Base=lambda: base, __version__='4.14.0',
                           exceptions=SimpleNamespace(MarkingError=MarkingError, DepsolveError=DepsolveError))


def measured_condition(crb=True, base=None):
    with tempfile.TemporaryDirectory() as directory:
        return w.condition(fake_dnf(base or Base()), directory, crb)


def report():
    state = {'count': 10, 'sha256': 'a' * 64}
    return {'schema': w.SCHEMA, 'status': w.SUCCESS, 'python': '3.9.19', 'dnf': '4.14.0', 'rpm': '4.16.1.3',
            'scope': 'metadata_and_solver_only',
            'conditions': [measured_condition(False), measured_condition(True)],
            'rpm_before_after': state, 'configuration_before_after': state,
            'system_state_unchanged': True, 'rpm_downloaded': False, 'transaction_executed': False,
            'build_verified': False, 'crb_on_resolved': True}


class WorkerTests(unittest.TestCase):
    def test_crb_off_missing_candidate_does_not_solve(self):
        base = Base()
        row = measured_condition(False, base)
        self.assertEqual(row['missing'], ['libyaml-devel'])
        self.assertEqual(row['resolution'], 'MISSING_CANDIDATES')
        base.install.assert_not_called()
        base.resolve.assert_not_called()

    def test_crb_on_solves_all_and_never_installs_downloads_or_plugins(self):
        base = Base()
        row = measured_condition(True, base)
        self.assertEqual(row['resolution'], 'RESOLVED')
        self.assertEqual([c.args[0] for c in base.install.call_args_list], list(w.PACKAGES))
        self.assertTrue(all(c.kwargs == {'strict': True} for c in base.install.call_args_list))
        base.resolve.assert_called_once_with(allow_erasing=False)
        base.do_transaction.assert_not_called()
        base.download_packages.assert_not_called()
        base.init_plugins.assert_not_called()

    def test_baseline_and_process_only_repo_flags(self):
        base = Base()
        with tempfile.TemporaryDirectory() as directory:
            baseline, selected = w.configure(base, directory, False)
            self.assertEqual(baseline, ['appstream', 'baseos', 'extras-common'])
            self.assertEqual(selected, ['baseos', 'appstream'])
            self.assertFalse(base.repos['crb'].enabled)
            self.assertFalse(base.repos['extras-common'].enabled)
            for repo in list(base.repos.values())[:2]:
                self.assertFalse(repo.skip_if_unavailable)
                self.assertEqual((repo.timeout, repo.retries), (20, 1))
            for key in ('cachedir', 'persistdir', 'logdir'):
                self.assertEqual(Path(getattr(base.conf, key)).parent, Path(directory))

    def test_bad_baseline_rejected_before_metadata(self):
        for mutation in ('crb-enabled', 'missing'):
            base = Base()
            if mutation == 'crb-enabled':
                base.repos['crb'].enable()
            else:
                del base.repos['baseos']
            base.fill_sack = Mock()
            with self.assertRaises(w.Stop):
                measured_condition(True, base)
            base.fill_sack.assert_not_called()

    def test_tls_bypass_credentials_proxy_and_bad_scheme_rejected(self):
        for changes in ({'sslverify': False}, {'gpgcheck': False}, {'proxy': 'SECRET'},
                        {'username': 'SECRET'}, {'sslclientkey': 'SECRET'},
                        {'metalink': 'https://SECRET@example.invalid/'},
                        {'baseurl': ['file:///not-allowed']}):
            with self.subTest(changes=changes), self.assertRaises(w.Stop) as exc:
                w.check_transport(configuration(**changes))
            self.assertNotIn('SECRET', str(exc.exception))

    def test_solver_errors_are_categories_not_error_text(self):
        for error, expected in ((MarkingError, 'MARKING_FAILED'), (DepsolveError, 'DEPSOLVE_FAILED')):
            base = Base()
            base.resolve.side_effect = error('SECRET')
            row = measured_condition(True, base)
            self.assertEqual(row['resolution'], expected)
            self.assertNotIn('SECRET', json.dumps(row))
            self.assertFalse(row['install_set'])

    def test_replacement_and_erasure_are_reported_as_plans(self):
        base = Base()
        base.transaction.remove_set = [pkg(repo='@System'), pkg('old-package', '@System')]
        row = measured_condition(True, base)
        self.assertEqual(row['planned_replacements'], ['gcc'])
        self.assertEqual({p['name'] for p in row['remove_set']}, {'gcc', 'old-package'})
        base.do_transaction.assert_not_called()

    def test_already_installed_requested_packages_are_not_marked_for_update(self):
        base = Base()
        original = base.fill_sack
        def fill(**kwargs):
            original(**kwargs)
            base.sack = SimpleNamespace(query=lambda: Query([pkg(n, '@System') for n in w.PACKAGES]))
        base.fill_sack = fill
        value = measured_condition(True, base)
        self.assertEqual(value['resolution'], 'RESOLVED')
        self.assertFalse(value['install_set'])
        base.install.assert_not_called()
        base.resolve.assert_not_called()

    def test_unexpected_arch_repo_and_oversize_rejected(self):
        for change in ({'arch': 'aarch64'}, {'reponame': 'third-party'}, {'name': 'SECRET\nDATA'}):
            item = pkg()
            item.__dict__.update(change)
            with self.assertRaises(w.Stop):
                w.package(item)
        with self.assertRaises(w.Stop):
            w.rows([pkg()] * 257)

    def test_rpm_state_order_independent_and_changes_detected(self):
        one = {'name': 'gcc', 'epoch': 0, 'version': '1', 'release': '1', 'arch': 'x86_64'}
        two = dict(one, name='make')
        rpm = SimpleNamespace(TransactionSet=lambda: SimpleNamespace(dbMatch=lambda: [one, two]))
        first = w.rpm_state(rpm)
        rpm.TransactionSet = lambda: SimpleNamespace(dbMatch=lambda: [two, one])
        self.assertEqual(w.rpm_state(rpm), first)
        two['version'] = '2'
        self.assertNotEqual(w.rpm_state(rpm), first)

    def test_measure_compares_state_even_when_metadata_fails(self):
        for fail, changed in ((False, False), (False, True), (True, False), (True, True)):
            with tempfile.TemporaryDirectory() as directory, \
                    patch.object(w, 'rpm_state', side_effect=[{'count': 1}, {'count': 2 if changed else 1}]), \
                    patch.object(w, 'configuration_state', return_value={'count': 1}), \
                    patch.object(w, 'condition', side_effect=RuntimeError('SECRET') if fail else None,
                                 return_value={'resolution': 'RESOLVED'}) as condition:
                if fail or changed:
                    with self.assertRaises(w.Stop if changed else RuntimeError):
                        w.measure(SimpleNamespace(__version__='4.14'), SimpleNamespace(__version__='4.16'), directory)
                else:
                    value = w.measure(SimpleNamespace(__version__='4.14'), SimpleNamespace(__version__='4.16'), directory)
                    self.assertTrue(value['system_state_unchanged'])
                    self.assertEqual([c.args[2] for c in condition.call_args_list], [False, True])


class HostTests(unittest.TestCase):
    def test_schema_accepts_measured_comparison(self):
        h.validate(report(), w)

    def test_schema_rejects_wrong_inputs_and_claims(self):
        value = report()
        mutations = [lambda v: v.update(build_verified=True), lambda v: v.update(rpm_downloaded=True),
                     lambda v: v.update(transaction_executed=True), lambda v: v.update(SECRET='SECRET'),
                     lambda v: v['conditions'].reverse(),
                     lambda v: v['conditions'][0].update(missing=[]),
                     lambda v: v['conditions'][0].update(elapsed_seconds=float('nan')),
                     lambda v: v['conditions'][1]['install_set'][0].update(reponame='third-party'),
                     lambda v: v['conditions'][1].update(planned_replacements=['gcc']),
                     lambda v: v.update(crb_on_resolved=False)]
        for mutation in mutations:
            changed = copy.deepcopy(value)
            mutation(changed)
            with self.assertRaises(h.Stop):
                h.validate(changed, w)

    def test_container_limits_and_no_host_access(self):
        args = h.arguments(runtime, 'test', 'identity')
        for value in ('--read-only', '--cap-drop', 'ALL', 'no-new-privileges', '65534:65534',
                      '2g', '/tmp:rw,nosuid,nodev,noexec,size=1g,mode=1777'):
            self.assertIn(value, args)
        for value in ('--mount', '--volume', '-v', '--privileged', '--publish'):
            self.assertNotIn(value, args)
        self.assertEqual(args[args.index('--network') + 1], 'bridge')
        self.assertEqual(args[-4:], [runtime.TARGET_CONFIG, '-I', '-B', '-'])

    def test_no_authorization_no_side_effects(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(h, 'load') as load_mock, \
                patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(io.StringIO()):
            path = Path(directory) / 'report.json'
            self.assertEqual(h.main(['--output', str(path)]), 3)
            self.assertFalse(path.exists())
            load_mock.assert_not_called()

    def run_host(self, value=None, rc=0, stderr='', cleanup=True, timeout=False):
        rt = SimpleNamespace(**{k: getattr(runtime, k) for k in ('DOCKER', 'TARGET', 'TARGET_CONFIG', 'TARGET_MANIFEST')})
        rt.command, rt.inspect_image, rt.cleanup = Mock(return_value=''), Mock(return_value={}), Mock(return_value=cleanup)
        inv = SimpleNamespace(now=lambda: '2026-11-15T00:00:00Z', registry_identity=lambda *a: {
            'platform_manifest_digest': runtime.TARGET_MANIFEST, 'config_digest': runtime.TARGET_CONFIG})
        modules = {'runtime_smoke': rt, 'env_probe': inv, 'dependency_container_probe': w}
        proc = SimpleNamespace(returncode=rc, stdout=json.dumps(report() if value is None else value), stderr=stderr)
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': h.BRANCH}, clear=True), \
                patch.object(h.platform, 'system', return_value='Linux'), \
                patch.object(h.platform, 'machine', return_value='x86_64'), \
                patch.object(h, 'load', side_effect=modules.__getitem__), \
                patch.object(h.os, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=0)), \
                patch.object(h.subprocess, 'run', return_value=proc,
                             side_effect=subprocess.TimeoutExpired('mock', 1) if timeout else None), \
                contextlib.redirect_stdout(io.StringIO()):
            path = Path(directory) / 'report.json'
            result = h.main(['--output', str(path), '--allow-pull', '--ephemeral-ci', '--allow-repo-metadata', '--allow-solver'])
            saved = json.loads(path.read_text())
        return result, saved, rt

    def test_success_and_incomplete_phase_flags(self):
        rc, value, rt = self.run_host()
        self.assertEqual((rc, value['status']), (0, w.SUCCESS))
        self.assertFalse(value['p1_03_complete'])
        self.assertFalse(value['phase1_complete'])
        self.assertTrue(value['cleanup_confirmed'])
        rt.cleanup.assert_called_once()

    def test_crb_on_failure_keeps_comparison_without_success(self):
        value = report()
        value['conditions'][1].update(resolution='DEPSOLVE_FAILED', install_set=[])
        value['crb_on_resolved'] = False
        rc, saved, _ = self.run_host(value=value)
        self.assertEqual(rc, 3)
        self.assertEqual(saved['reason'], 'CRB_ON_NOT_RESOLVED')
        self.assertIn('measurement', saved)

    def test_cleanup_failure_timeout_stderr_exit_and_worker_failure(self):
        cases = [({'cleanup': False}, 'CLEANUP_UNCONFIRMED'), ({'timeout': True}, 'COMMAND_TIMEOUT'),
                 ({'stderr': 'SECRET'}, 'WORKER_OUTPUT_REJECTED'), ({'rc': 3}, 'WORKER_EXIT_MISMATCH'),
                 ({'value': {'status': 'INCOMPLETE', 'reason': 'SECRET', 'detail': 'SECRET'}, 'rc': 3},
                  'DEPENDENCY_MEASUREMENT_INCOMPLETE')]
        for kwargs, reason in cases:
            rc, value, rt = self.run_host(**kwargs)
            self.assertEqual((rc, value['reason']), (3, reason))
            self.assertNotIn('SECRET', json.dumps(value))
            rt.cleanup.assert_called_once()

    def test_config_retains_gates_and_single_job(self):
        config = yaml.safe_load((ROOT / '.circleci/config.yml').read_text())
        self.assertFalse(config['parameters']['run_p1_env_probe']['default'])
        workflow = config['workflows']['p1-environment-measurement']
        self.assertEqual(workflow['jobs'], ['p1-environment'])
        self.assertEqual(workflow['when']['and'], ['<< pipeline.parameters.run_p1_env_probe >>',
                         {'equal': [h.BRANCH, '<< pipeline.git.branch >>']}])
        job = config['jobs']['p1-environment']
        self.assertEqual(job['machine']['image'], 'ubuntu-2204:2023.10.1')
        self.assertEqual(job['resource_class'], 'medium')
        command = job['steps'][1]['run']['command']
        self.assertIn('scripts/p1/dependency_probe.py', command)
        self.assertIn('--allow-repo-metadata --allow-solver', command)
        self.assertNotIn('--allow-source-download', command)
        self.assertIn('30s 16m', command)
        self.assertEqual(job['steps'][1]['run']['no_output_timeout'], '17m')


if __name__ == '__main__':
    unittest.main()
