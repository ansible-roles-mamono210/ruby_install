"""Regressions for preserving discovery and private diagnostics in a read-only probe."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('home_inventory', ROOT / 'scripts/p1/container_probe.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class CollectionHomeTests(unittest.TestCase):
    def test_custom_discovery_order_and_scan_policy_survive_home_isolation(self):
        paths = ['/opt/installed collections', '/home/circleci/.ansible/collections',
                 '/usr/share/ansible/collections', '/opt/installed collections']
        original = {'HOME': '/home/circleci', 'RUBY_P1_CONTROLLER_CHECKS': '1',
                    'ANSIBLE_GALAXY_CACHE_DIR': '/tmp/ansible-galaxy-cache',
                    'ANSIBLE_LOCAL_TEMP': '/tmp/ansible-local',
                    'ANSIBLE_HOME': '/existing-home', 'PRIVATE_FIXTURE': 'not-output'}
        for scan in (True, False):
            with self.subTest(scan=scan), patch.dict(os.environ, original, clear=True), \
                    patch.object(c, 'collection_settings', return_value=(paths, scan)):
                child, mode = c.collection_environment()
                self.assertEqual(child['ANSIBLE_COLLECTIONS_PATH'].split(os.pathsep), paths)
                self.assertEqual(child['ANSIBLE_COLLECTIONS_SCAN_SYS_PATH'], str(scan).lower())
                self.assertEqual(child['ANSIBLE_HOME'], '/tmp/ruby-p1-ansible-home')
                self.assertEqual(child['HOME'], original['HOME'])
                self.assertEqual(mode, 'ISOLATED_HOME_SEARCH_PRESERVED')
                self.assertEqual(dict(os.environ), original)
                changed = {key for key in set(child) | set(original) if child.get(key) != original.get(key)}
                self.assertEqual(changed, {'ANSIBLE_HOME', 'ANSIBLE_COLLECTIONS_PATH', 'ANSIBLE_COLLECTIONS_SCAN_SYS_PATH'})

    def test_other_probe_modes_do_not_import_ansible_or_change_environment(self):
        for flag in (None, '0'):
            original = {'HOME': '/custom-home'}
            if flag is not None:
                original['RUBY_P1_CONTROLLER_CHECKS'] = flag
            with patch.dict(os.environ, original, clear=True), \
                    patch.object(c, 'collection_settings', side_effect=AssertionError('must not read settings')):
                child, mode = c.collection_environment()
                self.assertEqual(child, original)
                self.assertEqual(mode, 'ORIGINAL')

    def test_unrepresentable_search_settings_stop_before_any_child_process(self):
        invalid = [(None, True), ([], True), ('/opt/collections', True),
                   (['relative'], True), (['/a:/b'], True), (['/private\nSECRET'], True),
                   (['/private\x00SECRET'], True), ([None], True), (['/valid'], 'true')]
        for values in invalid:
            with self.subTest(values=values), patch.dict(os.environ, {'RUBY_P1_CONTROLLER_CHECKS': '1'}), \
                    patch.object(c, 'collection_settings', return_value=values), \
                    patch.object(c.subprocess, 'run') as run:
                result, text = c.collection_command()
                run.assert_not_called()
                self.assertEqual(result['state'], 'CONFIGURATION_ERROR')
                self.assertEqual(result['environment_mode'], 'UNCONFIRMED')
                self.assertIsNone(result['returncode'])
                self.assertEqual(text, '')
                self.assertNotIn('SECRET', json.dumps(result))

    def test_configuration_exception_does_not_leak_values_or_fall_back(self):
        for error in (ImportError('PRIVATE_FIXTURE'), RuntimeError('/private/PRIVATE_FIXTURE')):
            with patch.dict(os.environ, {'RUBY_P1_CONTROLLER_CHECKS': '1'}), \
                    patch.object(c, 'collection_settings', side_effect=error), \
                    patch.object(c.subprocess, 'run') as run:
                result, text = c.collection_command()
                run.assert_not_called()
                self.assertEqual(result['state'], 'CONFIGURATION_ERROR')
                self.assertEqual(text, '')
                self.assertNotIn('PRIVATE_FIXTURE', json.dumps(result))

    def test_scoped_child_change_keeps_single_command_and_warning_rejection(self):
        stderr = b"[Errno 30] Read-only file system: '/tmp/ruby-p1-ansible-home/PRIVATE_FIXTURE'"
        process = subprocess.CompletedProcess([], 0, b'{}', stderr)
        with patch.dict(os.environ, {'RUBY_P1_CONTROLLER_CHECKS': '1', 'HOME': '/home/circleci'}), \
                patch.object(c, 'collection_settings', return_value=(['/opt/collections'], True)), \
                patch.object(c.subprocess, 'run', return_value=process) as run:
            result, text = c.collection_command()
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0], ['ansible-galaxy', 'collection', 'list', '--format', 'json'])
        self.assertEqual(run.call_args.kwargs['timeout'], 30)
        self.assertEqual(run.call_args.kwargs['env']['ANSIBLE_HOME'], '/tmp/ruby-p1-ansible-home')
        self.assertTrue(result['stderr_review_required'])
        self.assertEqual(result['stderr_path_classes'], ['TMP_ANSIBLE_HOME'])
        self.assertEqual(result['stderr_bytes'], len(stderr))
        self.assertEqual(text, '{}')
        self.assertNotIn('PRIVATE_FIXTURE', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
