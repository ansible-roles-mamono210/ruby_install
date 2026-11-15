"""Safety gates and evidence validation for the r27 installation proposal."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1] / 'scripts/p1'


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


host = module('install_probe')
worker = module('install_container_probe')
dep = module('dependency_container_probe')
dep_host = module('dependency_probe')
PLAN = json.loads((ROOT / 'ci416_dependency_plan.json').read_text())


def fixture():
    return {'schema': worker.SCHEMA, 'status': worker.SUCCESS, 'stage': 'finished',
            'rpm_downloaded': True, 'all_signatures_verified': True,
            'transaction_started': True, 'transaction_returned': True,
            'ruby_build_verified': False, 'p1_03_complete': False, 'phase1_complete': False,
            'imported_key_fingerprints': [], 'root_free_bytes_before': worker.MIN_FREE,
            'rpm_before': PLAN['baseline_rpm'], 'configuration_before': PLAN['baseline_configuration'],
            'configuration_after': PLAN['baseline_configuration'],
            'substitutions': {'state': 'LOADED', 'before': dict.fromkeys(dep.SUBSTITUTION_EXPECTED, 'EXPECTED'),
                              'after': dict.fromkeys(dep.SUBSTITUTION_EXPECTED, 'EXPECTED')},
            'transaction_plan_matches_ci416': True,
            'plan': {k: PLAN[k] for k in ('install_set', 'remove_set')},
            'public_key_file_sha256': ['a' * 64],
            'rpms': [{'package': r, 'sha256': 'b' * 64, 'bytes': 100, 'signature_verified': True}
                     for r in PLAN['install_set']],
            'delta': {'added_or_upgraded': 30, 'replaced_old_versions': 9, 'new_package_names': 21,
                      'public_keys_added': 0, 'exact_plan_match': True},
            'rpm_after': {'count': 184, 'sha256': 'c' * 64}, 'candidates_present': list(dep.PACKAGES),
            'rpm_tsflags': [], 'transaction_error_count': 0,
            'smoke': [{'name': name, 'returncode': 0, 'stderr_bytes': 0, 'output_match': True,
                       'elapsed_seconds': 0.1} for name in worker.SMOKE_NAMES], 'elapsed_seconds': 20.0}


class PlanTests(unittest.TestCase):
    def test_plan_matches_and_compares_all_nine_replacements(self):
        compare = Mock(return_value=1)
        worker.check_plan(PLAN['install_set'], PLAN['remove_set'], PLAN, compare)
        self.assertEqual(compare.call_count, 9)

    def test_changed_nevra_or_origin_stops(self):
        for field in ('version', 'release', 'reponame', 'arch'):
            rows = copy.deepcopy(PLAN['install_set'])
            rows[0][field] = 'changed'
            with self.subTest(field=field), self.assertRaisesRegex(worker.Stop, 'TRANSACTION_PLAN_CHANGED'):
                worker.check_plan(rows, PLAN['remove_set'], PLAN, Mock(return_value=1))

    def test_additional_package_stops(self):
        with self.assertRaisesRegex(worker.Stop, 'TRANSACTION_PLAN_CHANGED'):
            worker.check_plan(PLAN['install_set'] + [PLAN['install_set'][0]], PLAN['remove_set'], PLAN, Mock())

    def test_downgrade_and_reinstall_stop(self):
        for comparison in (0, -1):
            with self.subTest(comparison=comparison), self.assertRaisesRegex(worker.Stop, 'NON_UPGRADE_REPLACEMENT'):
                worker.check_plan(PLAN['install_set'], PLAN['remove_set'], PLAN, Mock(return_value=comparison))

    def test_unpaired_removal_stops_even_if_plan_is_tampered(self):
        plan = copy.deepcopy(PLAN)
        plan['remove_set'][0]['name'] = 'unrelated'
        with self.assertRaisesRegex(worker.Stop, 'UNPAIRED_REMOVAL'):
            worker.check_plan(plan['install_set'], plan['remove_set'], plan, Mock(return_value=1))

    def inventories(self):
        retained = {'name': 'retained', 'epoch': '0', 'version': '1', 'release': '1', 'arch': 'noarch'}
        before = [retained] + PLAN['remove_set']
        after = [retained] + PLAN['install_set']
        return before, after

    def test_exact_delta(self):
        before, after = self.inventories()
        result = worker.check_delta(before, after, PLAN)
        self.assertTrue(result['exact_plan_match'])
        self.assertEqual(result['new_package_names'], 21)

    def test_unrelated_removal_and_extra_install_stop(self):
        before, after = self.inventories()
        for changed in (after[1:], after + [dict(after[0], name='extra')]):
            with self.assertRaisesRegex(worker.Stop, 'RPM_DELTA'):
                worker.check_delta(before, changed, PLAN)

    def test_key_addition_separate_from_package_delta(self):
        before, after = self.inventories()
        public_key = dict(after[0], name='gpg-pubkey')
        self.assertEqual(worker.check_delta(before, after + [public_key], PLAN)['public_keys_added'], 1)
        with self.assertRaisesRegex(worker.Stop, 'RPM_DELTA'):
            worker.check_delta(before + [public_key], after, PLAN)

    def test_duplicate_rpm_is_not_silently_deduplicated(self):
        before, after = self.inventories()
        with self.assertRaisesRegex(worker.Stop, 'RPM_DELTA'):
            worker.check_delta(before, after + [after[0]], PLAN)


class SignatureTests(unittest.TestCase):
    def test_remote_key_is_rejected(self):
        base = SimpleNamespace(repos=SimpleNamespace(iter_enabled=lambda: [SimpleNamespace(
            gpgkey=['https://example.invalid/key'])]))
        with self.assertRaisesRegex(worker.Stop, 'KEY_SOURCE'):
            worker.trusted_keys(base)

    def test_key_outside_packaged_directory_is_rejected(self):
        for uri in ('file:///tmp/key', 'file://remote/etc/pki/rpm-gpg/key',
                    'file:///etc/pki/rpm-gpg/%2e%2e/key'):
            base = SimpleNamespace(repos=SimpleNamespace(iter_enabled=lambda: [SimpleNamespace(gpgkey=[uri])]))
            with self.subTest(uri=uri), self.assertRaisesRegex(worker.Stop, 'KEY_SOURCE'):
                worker.trusted_keys(base)

    def test_download_limit_precedes_network(self):
        base = Mock()
        p = SimpleNamespace(downloadsize=worker.MAX_DOWNLOAD + 1, installsize=1)
        with self.assertRaisesRegex(worker.Stop, 'DOWNLOAD_LIMIT'):
            worker.download_and_verify(base, [p], {}, dep)
        base.download_packages.assert_not_called()

    def verify(self, signature=0, checksum=True):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'package.rpm'
            path.write_bytes(b'fixture-only')
            package = SimpleNamespace(**PLAN['install_set'][0], downloadsize=12, installsize=20,
                                      localPkg=lambda: str(path), verifyLocalPkg=lambda: checksum)
            base = Mock()
            base.conf = SimpleNamespace(cachedir=directory)
            base.package_signature_check.return_value = (signature, 'UNTRUSTED_SECRET_NOT_FOR_OUTPUT')
            report = {'imported_key_fingerprints': []}
            with patch.object(worker, 'trusted_keys', return_value={'file:///unused': 'a' * 64}):
                worker.download_and_verify(base, [package], report, dep)
            return report, base

    def test_signature_is_verified_before_success(self):
        report, base = self.verify()
        self.assertTrue(report['all_signatures_verified'])
        base.download_packages.assert_called_once()
        base.package_signature_check.assert_called_once()
        base.do_transaction.assert_not_called()

    def test_bad_signature_stops(self):
        with self.assertRaisesRegex(worker.Stop, 'RPM_SIGNATURE'):
            self.verify(signature=2)

    def test_checksum_failure_stops(self):
        with self.assertRaisesRegex(worker.Stop, 'RPM_CHECKSUM'):
            self.verify(checksum=False)


class EvidenceTests(unittest.TestCase):
    def validate(self, value):
        host.validate(value, PLAN, worker, dep_host, dep)

    def test_success_evidence(self):
        self.validate(fixture())

    def test_partial_or_boolean_counts_rejected(self):
        changes = [('transaction_returned', False), ('all_signatures_verified', False),
                   ('p1_03_complete', True), ('phase1_complete', True), ('ruby_build_verified', True),
                   ('elapsed_seconds', float('nan')), ('root_free_bytes_before', True),
                   ('transaction_error_count', 1), ('transaction_error_count', False)]
        for field, value in changes:
            result = fixture(); result[field] = value
            with self.subTest(field=field), self.assertRaises(host.Stop):
                self.validate(result)

    def test_duplicate_rpm_rejected(self):
        result = fixture(); result['rpms'][0] = result['rpms'][1]
        with self.assertRaises(host.Stop):
            self.validate(result)

    def test_smoke_failure_and_bool_exit_rejected(self):
        for field, value in [('returncode', False), ('stderr_bytes', 1), ('output_match', False)]:
            result = fixture(); result['smoke'][1][field] = value
            with self.subTest(field=field), self.assertRaises(host.Stop):
                self.validate(result)

    def test_failure_never_copies_raw_details(self):
        value = {'schema': worker.SCHEMA, 'stage': 'download', 'reason': 'API_OR_RUNTIME_ERROR',
                 'raw_exception': 'SECRET', 'url': 'SECRET', 'transaction_started': False}
        result = host.failure(value, worker)
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertIs(result['transaction_started'], False)

    def test_invalid_failure_types(self):
        result = host.failure({'schema': worker.SCHEMA, 'stage': [], 'reason': []}, worker)
        self.assertEqual(result['reason'], 'UNCLASSIFIED')

    def test_simulated_or_scriptless_transaction_rejected(self):
        for flag in ('test', 'justdb', 'noscripts', 'nocrypto'):
            result = fixture(); result['rpm_tsflags'] = [flag]
            with self.subTest(flag=flag), self.assertRaises(host.Stop):
                self.validate(result)


class ExecutionOrderTests(unittest.TestCase):
    def setup_base(self):
        base = Mock()
        base.__enter__ = Mock(return_value=base)
        base.__exit__ = Mock(return_value=False)
        base.conf = SimpleNamespace(installroot='/', tsflags=[], downloadonly=False,
                                    gpgcheck=True, sslverify=True)
        base.sack.query.return_value.installed.return_value.filter.return_value = []
        class Transaction:
            install_set = [SimpleNamespace(**r) for r in PLAN['install_set']]
            remove_set = [SimpleNamespace(**r) for r in PLAN['remove_set']]
            def __iter__(self):
                return iter([SimpleNamespace(action=1)])
        base.transaction = Transaction()
        dnf = SimpleNamespace(Base=lambda: base, callback=SimpleNamespace(TransactionProgress=object), transaction=SimpleNamespace(
            PKG_INSTALL=1, PKG_UPGRADE=2, PKG_UPGRADED=3))
        rpm = SimpleNamespace(labelCompare=Mock(return_value=1))
        dependency = SimpleNamespace(PACKAGES=dep.PACKAGES, rows=dep.rows,
            rpm_state=Mock(return_value=PLAN['baseline_rpm']),
            configuration_state=Mock(return_value=PLAN['baseline_configuration']),
            configure=Mock(return_value=([], list(dep.REPOS), {})))
        return base, dnf, rpm, dependency

    def test_changed_baseline_stops_before_repository_or_transaction(self):
        base, dnf, rpm, dependency = self.setup_base()
        dependency.rpm_state.return_value = {'count': 999, 'sha256': 'f' * 64}
        with self.assertRaisesRegex(worker.Stop, 'BASELINE_CHANGED'):
            worker.execute(dependency, dnf, rpm, PLAN, '/tmp/unused', {})
        dependency.configure.assert_not_called()
        base.do_transaction.assert_not_called()

    def test_changed_plan_stops_before_download_and_transaction(self):
        base, dnf, rpm, dependency = self.setup_base()
        base.transaction.install_set[0].release = 'changed'
        with patch.object(worker, 'inventory', return_value=[]), \
                patch.object(worker, 'download_and_verify') as download:
            with self.assertRaisesRegex(worker.Stop, 'TRANSACTION_PLAN_CHANGED'):
                worker.execute(dependency, dnf, rpm, PLAN, '/tmp/unused', {})
        download.assert_not_called()
        base.do_transaction.assert_not_called()

    def test_signature_failure_prevents_transaction(self):
        base, dnf, rpm, dependency = self.setup_base()
        with patch.object(worker, 'inventory', return_value=[]), \
                patch.object(worker, 'download_and_verify', side_effect=worker.Stop('RPM_SIGNATURE')):
            with self.assertRaisesRegex(worker.Stop, 'RPM_SIGNATURE'):
                worker.execute(dependency, dnf, rpm, PLAN, '/tmp/unused', {})
        base.do_transaction.assert_not_called()

    def test_transaction_exactly_once_after_verification(self):
        base, dnf, rpm, dependency = self.setup_base()
        events = []
        base.do_transaction.side_effect = lambda **kwargs: events.append('transaction')
        before = PLAN['remove_set'] + [dict(PLAN['install_set'][0], name='retained')]
        after = PLAN['install_set'] + [dict(PLAN['install_set'][0], name='retained')]
        # All direct candidates, including already-installed packages, are represented.
        for name in ('tar', 'gzip', 'ca-certificates'):
            row = dict(before[-1], name=name); before.append(row); after.append(row)
        with patch.object(worker, 'inventory', side_effect=[before, after]), \
                patch.object(worker, 'download_and_verify', side_effect=lambda *a: events.append('verified')), \
                patch.object(worker, 'smoke'):
            report = {}
            worker.execute(dependency, dnf, rpm, PLAN, '/tmp/unused', report)
        self.assertEqual(events, ['verified', 'transaction'])
        base.do_transaction.assert_called_once()
        self.assertEqual(report['status'], worker.SUCCESS)

    def test_nonfatal_scriptlet_error_is_failure_and_message_is_not_retained(self):
        base = Mock()
        base.do_transaction.side_effect = lambda display: display.error('SECRET')
        report = {}
        with self.assertRaisesRegex(worker.Stop, 'TRANSACTION_CALLBACK_ERROR'):
            worker.run_transaction(base, object, report)
        self.assertTrue(report['transaction_returned'])
        self.assertEqual(report['transaction_error_count'], 1)
        self.assertNotIn('SECRET', json.dumps(report))


class HostTests(unittest.TestCase):
    def test_container_has_no_host_bind_socket_privilege_or_host_network(self):
        runtime = SimpleNamespace(DOCKER=['docker', '--host', 'unix:///var/run/docker.sock'], TARGET_CONFIG='sha256:x')
        args = host.arguments(runtime, 'owned-name', 'owned-id')
        for bad in ('--privileged', '--mount', '-v', '--read-only'):
            self.assertNotIn(bad, args)
        self.assertEqual(args[args.index('--network') + 1], 'bridge')
        self.assertEqual(args[args.index('--user') + 1], '0:0')
        self.assertIn('no-new-privileges', args)
        self.assertNotIn('SYS_ADMIN', args)
        self.assertIn('/tmp:rw,nosuid,nodev,exec,size=1g,mode=1777', args)

    def test_missing_approval_flags_stop_without_output_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'result.json'
            with patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': host.BRANCH}):
                self.assertEqual(host.main(['--output', str(output)]), 3)
            self.assertFalse(output.exists())

    def run_host(self, cleanup=True, timeout=False):
        runtime = SimpleNamespace(DOCKER=['docker'], TARGET='fixed-target', TARGET_CONFIG='fixed-config',
                                  TARGET_MANIFEST='fixed-manifest', command=Mock(), inspect_image=Mock(),
                                  cleanup=Mock(return_value=cleanup))
        inventory = SimpleNamespace(now=lambda: 'fixture-time', registry_identity=lambda *a: {
            'platform_manifest_digest': 'fixed-manifest', 'config_digest': 'fixed-config'})
        modules = {'runtime_smoke': runtime, 'env_probe': inventory, 'install_container_probe': worker,
                   'dependency_probe': dep_host, 'dependency_container_probe': dep}
        outcome = subprocess.CompletedProcess([], 0, json.dumps(fixture()), '')
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'result.json'
            with patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': host.BRANCH}), \
                    patch.object(host, 'load', side_effect=modules.__getitem__), \
                    patch.object(host.os, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=0)), \
                    patch.object(host.subprocess, 'run', return_value=outcome,
                                 side_effect=subprocess.TimeoutExpired([], 960) if timeout else None):
                code = host.main(['--output', str(output), '--allow-pull', '--ephemeral-ci',
                                  '--allow-install', '--allow-ci416-replacements'])
            result = json.loads(output.read_text())
        runtime.cleanup.assert_called_once()
        return code, result

    def test_success_requires_cleanup(self):
        code, result = self.run_host()
        self.assertEqual(code, 0)
        self.assertTrue(result['cleanup_confirmed'])

    def test_cleanup_failure_downgrades_success(self):
        code, result = self.run_host(cleanup=False)
        self.assertEqual(code, 3)
        self.assertEqual(result['reason'], 'CLEANUP_UNCONFIRMED')

    def test_timeout_still_cleans(self):
        code, result = self.run_host(timeout=True)
        self.assertEqual(code, 3)
        self.assertEqual(result['reason'], 'COMMAND_TIMEOUT')

    def test_smoke_stops_after_first_failed_command(self):
        with tempfile.TemporaryDirectory() as directory:
            record = []
            with patch.object(worker.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'x')) as run:
                with self.assertRaisesRegex(worker.Stop, 'SMOKE_FAILED'):
                    worker.smoke(directory, record)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(record[0]['name'], 'fresh_python')
            self.assertEqual(record[0]['returncode'], 1)


if __name__ == '__main__':
    unittest.main()
