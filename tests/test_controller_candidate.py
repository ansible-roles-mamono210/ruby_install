"""Offline candidate regressions: no registry, Docker or CI access."""
import contextlib
import copy
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
SPEC = importlib.util.spec_from_file_location('candidate_probe', ROOT / 'scripts/p1/env_probe.py')
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)


def compatible_row():
    return {
        'status': 'COLLECTED', 'cleanup_confirmed': True,
        'probe': {
            'arch': 'x86_64', 'python': '3.14.10',
            'packages': dict(p.EXPECTED), 'collections_status': 'COLLECTED',
            'collections': [{'name': name, 'version': version}
                            for name, version in p.COLLECTIONS.items()],
            'collections_diagnostic': {'state': 'EXITED', 'returncode': 0},
        },
    }


class ControllerCandidateTests(unittest.TestCase):
    def setUp(self):
        self.signals = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}

    def tearDown(self):
        for s, handler in self.signals.items():
            signal.signal(s, handler)

    def run_main(self, result):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'evidence.json'
            original_stat = p.os.stat

            def fake_stat(path, *args, **kwargs):
                if str(path) == '/var/run/docker.sock':
                    return SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=0)
                return original_stat(path, *args, **kwargs)

            with patch.dict(os.environ, {'CIRCLECI': 'true'}), patch.object(p, 'host_inventory', return_value={}), patch.object(p.os, 'stat', side_effect=fake_stat), patch.object(p, 'parsed', return_value={}), patch.object(p, 'collect_image', return_value=result) as collect, contextlib.redirect_stdout(io.StringIO()):
                rc = p.main(['--mode', 'controller-candidate', '--allow-pull',
                             '--ephemeral-ci', '--output', str(output)])
            return rc, json.loads(output.read_text()), collect.call_args_list

    def test_only_one_candidate_container_and_pull_are_requested(self):
        rc, report, calls = self.run_main(compatible_row())
        self.assertEqual(rc, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].args[:3], ('controller', p.CANDIDATE_CONTROLLER, True))
        self.assertEqual(calls[0].kwargs, {'galaxy_cache': 'tmp',
                                         'expected_image_id': p.CANDIDATE_CONFIG_DIGEST})
        self.assertEqual(list(report['images']), ['controller'])
        self.assertEqual(report['expected_packages'], p.EXPECTED)
        self.assertEqual(report['expected_collections'], p.COLLECTIONS)
        self.assertEqual(report['status'], 'CANDIDATE_INVENTORY_COLLECTED_ONLY')
        self.assertFalse(report['p1_02_complete'])
        self.assertIn('candidate_target_smoke', report['remaining'])

    def test_version_mismatch_returns_four_and_is_not_adopted(self):
        row = compatible_row()
        row['probe']['packages']['ansible-core'] = '2.20.3'
        rc, report, calls = self.run_main(row)
        self.assertEqual(rc, 4)
        self.assertEqual(report['status'], 'CANDIDATE_MISMATCH')
        self.assertFalse(report['p1_02_complete'])
        self.assertEqual(len(calls), 1)

    def test_failure_timeout_missing_data_or_cleanup_never_succeeds(self):
        for defect in ['image', 'cleanup', 'status', 'timeout', 'rc', 'boolean_rc', 'missing']:
            with self.subTest(defect=defect):
                row = compatible_row()
                if defect == 'image':
                    row['status'] = 'INCOMPLETE'
                elif defect == 'cleanup':
                    row['cleanup_confirmed'] = False
                elif defect == 'status':
                    row['probe']['collections_status'] = 'COMMAND_FAILED'
                elif defect == 'timeout':
                    row['probe']['collections_diagnostic']['state'] = 'TIMEOUT'
                elif defect == 'rc':
                    row['probe']['collections_diagnostic']['returncode'] = 1
                elif defect == 'boolean_rc':
                    row['probe']['collections_diagnostic']['returncode'] = False
                else:
                    del row['probe']['collections_diagnostic']
                self.assertEqual(p.candidate_summary(row), ('INCOMPLETE', 3))

    def test_duplicate_same_version_at_another_location_is_incomplete(self):
        row = compatible_row()
        duplicate = copy.deepcopy(row['probe']['collections'][0])
        duplicate['location'] = '/another/search/path'
        row['probe']['collections'].append(duplicate)
        self.assertEqual(p.candidate_summary(row), ('INCOMPLETE', 3))

    def test_wrong_or_missing_collection_is_mismatch(self):
        for defect in ['version', 'absent']:
            row = compatible_row()
            if defect == 'version':
                row['probe']['collections'][0]['version'] = '0.0.0'
            else:
                row['probe']['collections'].pop(0)
            self.assertEqual(p.candidate_summary(row), ('CANDIDATE_MISMATCH', 4))

    def test_malformed_collection_data_stays_incomplete(self):
        for data in [None, {}, [None], [{'name': []}], [{'name': ''}], [{'name': 'community.general'}]]:
            row = compatible_row()
            row['probe']['collections'] = data
            self.assertEqual(p.candidate_summary(row), ('INCOMPLETE', 3))

    def test_stderr_hint_is_retained_without_becoming_phase_completion(self):
        row = compatible_row()
        row['probe']['collections_diagnostic']['stderr_hints'] = ['READ_ONLY_FILESYSTEM']
        row['probe']['collections_diagnostic']['stderr_bytes'] = 359
        rc, report, _ = self.run_main(row)
        self.assertEqual(rc, 0)
        self.assertFalse(report['p1_02_complete'])
        self.assertEqual(report['images']['controller']['probe']['collections_diagnostic']['stderr_hints'], ['READ_ONLY_FILESYSTEM'])
        self.assertIn('stderr_warning_review', report['remaining'])

    def test_known_config_mismatch_stops_before_container_execution(self):
        info = {'id': 'sha256:' + 'f' * 64, 'os': 'linux', 'arch': 'amd64'}
        with patch.object(p, 'parsed', return_value=info) as parsed, patch.object(p, 'registry_identity', return_value={}), patch.object(p, 'cleanup') as cleanup:
            row = p.collect_image('controller', p.CANDIDATE_CONTROLLER, False, 'fixture',
                                  None, 'pass', galaxy_cache='tmp',
                                  expected_image_id=p.CANDIDATE_CONFIG_DIGEST)
        self.assertEqual(row['error_code'], 'CANDIDATE_CONFIG_DIGEST_MISMATCH')
        self.assertEqual(row['status'], 'INCOMPLETE')
        self.assertEqual(parsed.call_count, 1)
        cleanup.assert_not_called()

    def test_candidate_keeps_container_isolation_and_known_id(self):
        info = {'id': p.CANDIDATE_CONFIG_DIGEST, 'os': 'linux', 'arch': 'amd64'}
        with patch.object(p, 'parsed', side_effect=[info, compatible_row()['probe']]) as parsed, patch.object(p, 'registry_identity', return_value={}), patch.object(p, 'cleanup', return_value=True) as cleanup:
            row = p.collect_image('controller', p.CANDIDATE_CONTROLLER, False, 'fixture',
                                  None, 'pass', galaxy_cache='tmp',
                                  expected_image_id=p.CANDIDATE_CONFIG_DIGEST)
        cmd = parsed.call_args_list[1].args[0]
        for flag in ['--pull=never', '--read-only', '--network', 'none', '--cap-drop',
                     'ALL', 'no-new-privileges', 'ANSIBLE_GALAXY_CACHE_DIR=/tmp/ansible-galaxy-cache']:
            self.assertIn(flag, cmd)
        for flag in ['--privileged', '-v', '--mount', '--user']:
            self.assertNotIn(flag, cmd)
        self.assertEqual(cmd[-2], p.CANDIDATE_CONFIG_DIGEST)
        self.assertTrue(row['cleanup_confirmed'])
        cleanup.assert_called_once()

    def test_candidate_requires_both_ephemeral_flag_and_circleci(self):
        for circleci, flag in [('false', True), ('true', False)]:
            with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'CIRCLECI': circleci}), contextlib.redirect_stderr(io.StringIO()):
                output = Path(directory) / 'evidence.json'
                args = ['--mode', 'controller-candidate', '--output', str(output)]
                if flag:
                    args.append('--ephemeral-ci')
                with self.assertRaises(SystemExit) as exc:
                    p.main(args)
                self.assertEqual(exc.exception.code, 2)
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
