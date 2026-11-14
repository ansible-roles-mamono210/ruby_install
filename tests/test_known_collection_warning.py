"""Offline replay of CI 378; mutations must not broaden the warning policy."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('warning_policy_runner', ROOT / 'scripts/p1/env_probe.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
FIXTURE = ROOT / 'tests/fixtures/controller-ci378.json'


def row():
    return json.loads(FIXTURE.read_text())['images']['controller']


class KnownCollectionWarningTests(unittest.TestCase):
    def rejects(self, evidence, code=6):
        result = p.controller_checks_summary(evidence)
        self.assertNotEqual(result[1], 0)
        self.assertEqual(result[1], code)

    def test_fixture_is_unchanged_actual_failed_run_not_a_pass_record(self):
        self.assertEqual(hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
                         '3ac51a2b53475fd23d4d639f4b3a35082b547bce678d55438e3ee985379366e9')
        actual = json.loads(FIXTURE.read_text())
        self.assertEqual((actual['status'], actual['exit_code']),
                         ('CONTROLLER_CHECKS_WARNING_REVIEW', 6))
        self.assertIs(actual['p1_02_complete'], False)

    def test_exact_fixture_replays_without_modifying_evidence(self):
        evidence = row()
        before = copy.deepcopy(evidence)
        self.assertEqual(p.controller_checks_summary(evidence), (p.KNOWN_WARNING_STATUS, 0))
        self.assertEqual(evidence, before)
        self.assertIs(evidence['probe']['collections_diagnostic']['stderr_review_required'], True)

    def test_image_reference_local_id_user_and_registry_are_bound(self):
        changes = [
            (('requested_ref',), 'other-image'),
            (('galaxy_cache_mode',), 'original'),
            (('image', 'id'), 'sha256:' + '0' * 64),
            (('image', 'repo_digests'), []),
            (('image', 'user'), 'root'),
            (('image', 'arch'), 'arm64'),
            (('image', 'os'), 'other'),
            (('registry', 'registry_reference'), 'other-image'),
            (('registry', 'config_digest'), 'sha256:' + '0' * 64),
            (('registry', 'platform_manifest_digest'), 'sha256:' + '0' * 64),
            (('registry', 'index_digest'), 'sha256:' + '0' * 64),
        ]
        for path, value in changes:
            with self.subTest(path=path):
                evidence = row()
                target = evidence
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.rejects(evidence)

    def test_missing_image_or_registry_evidence_is_not_exempted(self):
        for key in ('requested_ref', 'image', 'registry', 'galaxy_cache_mode'):
            with self.subTest(key=key):
                evidence = row()
                del evidence[key]
                self.rejects(evidence)

    def test_runtime_and_candidate_versions_remain_required(self):
        for name in p.EXPECTED:
            with self.subTest(package=name):
                evidence = row()
                evidence['probe']['packages'][name] = '0.0.0'
                self.rejects(evidence, 4)
        for key, value in [('python', '3.14.11'), ('uid', 0), ('uid', '1000'), ('uid', 1000.0)]:
            with self.subTest(key=key, value=value):
                evidence = row()
                evidence['probe'][key] = value
                self.rejects(evidence)

    def test_additional_unknown_and_repeated_warning_bytes_are_not_exempted(self):
        for byte_count, identity_updates in [
            (220, {'state': 'PARTIALLY_CLASSIFIED', 'unclassified_bytes': 1}),
            (438, {'matched_records': 2, 'matched_bytes': 438,
                   'message_counts': {'COLLECTION_METADATA_MISSING': 2},
                   'expected_internal_protomatter_records': 2}),
            (219, {'state': 'UNCLASSIFIED', 'matched_records': 0,
                   'matched_bytes': 0, 'unclassified_bytes': 219}),
            (219, {'expected_internal_protomatter_records': 0}),
        ]:
            with self.subTest(updates=identity_updates):
                evidence = row()
                diagnostic = evidence['probe']['collections_diagnostic']
                diagnostic['stderr_bytes'] = byte_count
                diagnostic['stderr_identity'].update(identity_updates)
                self.rejects(evidence)

    def test_missing_changed_or_additional_identity_fields_are_not_exempted(self):
        for key in row()['probe']['collections_diagnostic']['stderr_identity']:
            with self.subTest(missing=key):
                evidence = row()
                del evidence['probe']['collections_diagnostic']['stderr_identity'][key]
                self.rejects(evidence)
        for value in [None, {}, 'unclassified', {'new_schema': True}]:
            evidence = row()
            evidence['probe']['collections_diagnostic']['stderr_identity'] = value
            self.rejects(evidence)
        evidence = row()
        evidence['probe']['collections_diagnostic']['stderr_identity']['extra'] = True
        self.rejects(evidence)

    def test_identity_boolean_float_or_string_counters_are_not_integers(self):
        for key in ('matched_records', 'matched_bytes', 'unclassified_bytes',
                    'expected_internal_protomatter_records'):
            for kind in (bool, float, str):
                with self.subTest(key=key, kind=kind):
                    evidence = row()
                    identity = evidence['probe']['collections_diagnostic']['stderr_identity']
                    identity[key] = kind(identity[key])
                    self.rejects(evidence)
        for value in (True, 1.0, '1'):
            evidence = row()
            identity = evidence['probe']['collections_diagnostic']['stderr_identity']
            identity['message_counts']['COLLECTION_METADATA_MISSING'] = value
            self.rejects(evidence)

    def test_collection_diagnostic_context_and_hints_are_required(self):
        changes = [('environment_mode', 'ORIGINAL'), ('stderr_hints', ['PERMISSION_DENIED']),
                   ('stderr_path_classes', ['ROOT_CACHE']), ('stderr_review_required', False),
                   ('stderr_review_required', 1), ('stderr_bytes', 218)]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                evidence = row()
                evidence['probe']['collections_diagnostic'][key] = value
                self.rejects(evidence)

    def test_all_95_names_versions_locations_and_order_are_bound(self):
        for key in ('name', 'version', 'location'):
            with self.subTest(key=key):
                evidence = row()
                evidence['probe']['collections'][0][key] = 'changed'
                self.rejects(evidence)
        evidence = row()
        evidence['probe']['collections'].pop(0)
        self.rejects(evidence)
        evidence = row()
        evidence['probe']['collections'].append({'name': 'other.collection', 'version': '1', 'location': '/tmp'})
        self.rejects(evidence)
        evidence = row()
        evidence['probe']['collections'].reverse()
        self.rejects(evidence)
        evidence = row()
        evidence['probe']['collections'][0]['extra'] = 'unexpected'
        self.rejects(evidence)
        evidence = row()
        evidence['probe']['collections'][1]['version'] = None
        self.rejects(evidence)

    def test_duplicate_collections_and_cleanup_failure_still_stop(self):
        evidence = row()
        evidence['probe']['collections'][0] = copy.deepcopy(evidence['probe']['collections'][1])
        self.rejects(evidence, 3)
        evidence = row()
        evidence['cleanup_confirmed'] = False
        self.rejects(evidence, 3)

    def test_warning_on_each_other_command_is_never_exempted(self):
        for name in row()['probe']['controller_checks']['commands']:
            with self.subTest(command=name):
                evidence = row()
                evidence['probe']['controller_checks']['commands'][name]['stderr_bytes'] = 219
                self.rejects(evidence)

    def test_failure_timeout_and_bad_type_on_each_command_still_stop(self):
        for name in row()['probe']['controller_checks']['commands']:
            for key, value, code in [('returncode', 1, 5), ('state', 'TIMEOUT', 3),
                                     ('returncode', False, 3), ('stderr_bytes', False, 3)]:
                with self.subTest(command=name, key=key):
                    evidence = row()
                    evidence['probe']['controller_checks']['commands'][name][key] = value
                    self.rejects(evidence, code)

    def test_collection_failure_and_metadata_mismatch_still_stop(self):
        for key, value in [('returncode', 1), ('returncode', False), ('state', 'TIMEOUT')]:
            evidence = row()
            evidence['probe']['collections_diagnostic'][key] = value
            self.rejects(evidence, 3)
        evidence = row()
        checks = evidence['probe']['controller_checks']
        checks['metadata']['status'] = 'MISMATCH'
        checks['driver_checks'] = 'SKIPPED_METADATA_NOT_MATCHED'
        self.rejects(evidence, 5)
        for count, code in [(0, 5), (2, 5), (False, 3)]:
            evidence = row()
            evidence['probe']['controller_checks']['commands']['molecule_drivers']['docker_exact_lines'] = count
            self.rejects(evidence, code)

    def test_no_stderr_retains_existing_clean_status(self):
        evidence = row()
        evidence['probe']['collections_diagnostic']['stderr_bytes'] = 0
        self.assertEqual(p.controller_checks_summary(evidence), ('CONTROLLER_OFFLINE_CHECKS_PASSED_ONLY', 0))

    def test_inventory_only_mode_is_unchanged(self):
        self.assertEqual(p.candidate_summary(row()), ('CANDIDATE_INVENTORY_COLLECTED_ONLY', 0))

    def test_main_retains_warning_and_open_phase_in_separate_policy_record(self):
        signals = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        original = row()
        try:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'evidence.json'
                real_stat = p.os.stat
                def fake_stat(path, *args, **kwargs):
                    if str(path) == '/var/run/docker.sock':
                        return SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=0)
                    return real_stat(path, *args, **kwargs)
                with patch.dict(os.environ, {'CIRCLECI': 'true'}), \
                        patch.object(p, 'host_inventory', return_value={}), \
                        patch.object(p.os, 'stat', side_effect=fake_stat), \
                        patch.object(p, 'parsed', return_value={}), \
                        patch.object(p, 'collect_image', return_value=original) as collect, \
                        contextlib.redirect_stdout(io.StringIO()):
                    rc = p.main(['--mode', 'controller-checks', '--ephemeral-ci', '--output', str(output)])
                report = json.loads(output.read_text())
                self.assertEqual(rc, 0)
                self.assertEqual(collect.call_count, 1)
                self.assertEqual(report['status'], p.KNOWN_WARNING_STATUS)
                self.assertEqual(report['images']['controller'], original)
                self.assertEqual(report['warning_policy']['disposition'], 'KNOWN_WARNING_RETAINED')
                self.assertEqual(report['warning_policy']['id'], p.KNOWN_COLLECTION_WARNING_POLICY)
                self.assertIs(report['p1_02_complete'], False)
                for remaining in ('candidate_target_smoke', 'full_molecule_target_runtime',
                                  'lint_orb_execution_rules', 'CI_cost_limits'):
                    self.assertIn(remaining, report['remaining'])
                for resolved in ('candidate_pip_check', 'candidate_molecule_driver',
                                 'stderr_warning_review', 'controller_warning_review'):
                    self.assertNotIn(resolved, report['remaining'])
        finally:
            for sig, handler in signals.items():
                signal.signal(sig, handler)


if __name__ == '__main__':
    unittest.main()
