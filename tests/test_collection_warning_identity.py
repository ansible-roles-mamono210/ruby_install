"""Offline regressions for warning attribution without disclosure or exemption."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from test_controller_checks import compatible_row

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


c = load('warning_inventory', 'scripts/p1/container_probe.py')
p = load('warning_host', 'scripts/p1/env_probe.py')
checks = load('warning_checks', 'scripts/p1/controller_checks.py')
checks.warning_facts = c.warning_facts

# A synthesized fixture derived from upstream wording and the observed inventory.
# This is NOT the unrecorded stderr from CI376.
TARGET = (b'/home/circleci/.local/lib/python3.14/site-packages/ansible/'
          b'_internal/ansible_collections/ansible/_protomatter')


def missing_metadata(path=TARGET):
    return (b"[WARNING]: Collection at '" + path
            + b"' does not have a MANIFEST.json file, nor has it galaxy.yml: cannot detect version.\n")


class CollectionWarningIdentityTests(unittest.TestCase):
    def test_synthesized_hypothesis_has_219_bytes_and_full_identity(self):
        data = missing_metadata()
        self.assertEqual(len(data), 219)
        facts = c.warning_facts(data)
        identity = facts['stderr_identity']
        self.assertEqual(identity['state'], 'FULLY_CLASSIFIED')
        self.assertEqual(identity['matched_records'], 1)
        self.assertEqual(identity['matched_bytes'], 219)
        self.assertEqual(identity['unclassified_bytes'], 0)
        self.assertEqual(identity['expected_internal_protomatter_records'], 1)
        self.assertEqual(identity['message_counts'], {'COLLECTION_METADATA_MISSING': 1})
        self.assertTrue(facts['stderr_review_required'])

    def test_other_path_is_classified_without_emitting_it_or_claiming_target(self):
        data = missing_metadata(b'/private/credential=PRIVATE_FIXTURE')
        result = c.warning_facts(data)
        self.assertEqual(result['stderr_identity']['state'], 'FULLY_CLASSIFIED')
        self.assertEqual(result['stderr_identity']['expected_internal_protomatter_records'], 0)
        for value in ('PRIVATE_FIXTURE', '/private/', 'credential='):
            self.assertNotIn(value, json.dumps(result))

    def test_same_size_unknown_is_not_attributed_to_target(self):
        result = c.warning_facts(b'x' * 219)
        self.assertEqual(result['stderr_identity']['state'], 'UNCLASSIFIED')
        self.assertEqual(result['stderr_identity']['unclassified_bytes'], 219)
        self.assertEqual(result['stderr_identity']['expected_internal_protomatter_records'], 0)
        self.assertTrue(result['stderr_review_required'])

    def test_unknown_prefix_suffix_and_second_record_remain_accounted_for(self):
        known = missing_metadata()
        for data, expected in ((b'PRIVATE_FIXTURE\n' + known, 16),
                               (known + b'PRIVATE_FIXTURE', 15),
                               (known + b'\n', 1)):
            with self.subTest(expected=expected):
                identity = c.warning_facts(data)['stderr_identity']
                self.assertEqual(identity['state'], 'PARTIALLY_CLASSIFIED')
                self.assertEqual(identity['matched_bytes'], 219)
                self.assertEqual(identity['unclassified_bytes'], expected)
                self.assertEqual(identity['matched_bytes'] + identity['unclassified_bytes'], len(data))
                self.assertNotIn('PRIVATE_FIXTURE', json.dumps(identity))

    def test_multiple_known_records_keep_counts_and_byte_total(self):
        data = missing_metadata() + missing_metadata(b'/private/PRIVATE_FIXTURE') + missing_metadata()
        result = c.collection_warning_identity(data)
        self.assertEqual(result['state'], 'FULLY_CLASSIFIED')
        self.assertEqual(result['matched_records'], 3)
        self.assertEqual(result['expected_internal_protomatter_records'], 2)
        self.assertEqual(result['matched_bytes'], len(data))
        self.assertEqual(result['message_counts'], {'COLLECTION_METADATA_MISSING': 3})
        self.assertNotIn('PRIVATE_FIXTURE', json.dumps(result))

    def test_truncation_color_wrapping_and_modified_wording_are_not_normalized(self):
        known = missing_metadata()
        for data in (known[:-1], b'PREFIX ' + known, known[:-1] + b' SUFFIX\n',
                     b'\x1b[33m' + known + b'\x1b[0m', known.replace(b'\n', b'\r\n'),
                     known.replace(b'file, nor', b'file,\nnor'),
                     known.replace(b'cannot detect', b'can detect'), b'\xff\xfePRIVATE_FIXTURE'):
            with self.subTest(data_length=len(data)):
                result = c.collection_warning_identity(data)
                self.assertEqual(result['state'], 'UNCLASSIFIED')
                self.assertEqual(result['matched_bytes'], 0)
                self.assertEqual(result['unclassified_bytes'], len(data))

    def test_empty_and_over_limit_outputs_have_explicit_states(self):
        result = c.warning_facts(b'')
        self.assertFalse(result['stderr_review_required'])
        self.assertEqual(result['stderr_identity']['state'], 'EMPTY')
        data = missing_metadata() + b'x' * 65536
        result = c.warning_facts(data)
        self.assertTrue(result['stderr_review_required'])
        self.assertEqual(result['stderr_identity']['state'], 'SIZE_LIMIT')
        self.assertEqual(result['stderr_identity']['unclassified_bytes'], len(data))
        self.assertEqual(result['stderr_identity']['matched_records'], 0)

    def test_collection_command_keeps_one_invocation_environment_and_raw_count(self):
        data = missing_metadata()
        process = subprocess.CompletedProcess([], 0, b'{}', data)
        with patch.dict(os.environ, {'RUBY_P1_CONTROLLER_CHECKS': '1'}), \
                patch.object(c, 'collection_settings', return_value=(['/opt/collections'], True)), \
                patch.object(c.subprocess, 'run', return_value=process) as run:
            result, text = c.collection_command()
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0], ['ansible-galaxy', 'collection', 'list', '--format', 'json'])
        self.assertEqual(run.call_args.kwargs['timeout'], 30)
        self.assertEqual(run.call_args.kwargs['env']['ANSIBLE_HOME'], '/tmp/ruby-p1-ansible-home')
        self.assertEqual(result['stderr_bytes'], 219)
        self.assertEqual(result['stderr_identity']['state'], 'FULLY_CLASSIFIED')
        self.assertTrue(result['stderr_review_required'])
        self.assertEqual(text, '{}')

    def test_timeout_identity_does_not_turn_partial_execution_into_success(self):
        error = subprocess.TimeoutExpired('private command', 30, stderr=missing_metadata())
        with patch.dict(os.environ, {'RUBY_P1_CONTROLLER_CHECKS': '0'}), \
                patch.object(c.subprocess, 'run', side_effect=error):
            result, text = c.collection_command()
        self.assertEqual(result['state'], 'TIMEOUT')
        self.assertIsNone(result['returncode'])
        self.assertEqual(result['stderr_identity']['state'], 'FULLY_CLASSIFIED')
        self.assertEqual(text, '')

    def test_known_identity_on_any_command_still_requires_warning_review(self):
        for name in ['collections', *compatible_row()['probe']['controller_checks']['commands']]:
            row = compatible_row()
            command = (row['probe']['collections_diagnostic'] if name == 'collections'
                       else row['probe']['controller_checks']['commands'][name])
            command.update(stderr_bytes=219, **c.warning_facts(missing_metadata()))
            self.assertEqual(p.controller_checks_summary(row), ('CONTROLLER_CHECKS_WARNING_REVIEW', 6))

    def test_shared_controller_helper_does_not_expose_private_metadata_path(self):
        data = missing_metadata(b'/private/PRIVATE_FIXTURE')
        with patch.object(checks.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', data)):
            result, _ = checks.check_command(['fixture'])
        self.assertEqual(result['stderr_identity']['state'], 'FULLY_CLASSIFIED')
        self.assertTrue(result['stderr_review_required'])
        self.assertNotIn('PRIVATE_FIXTURE', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
