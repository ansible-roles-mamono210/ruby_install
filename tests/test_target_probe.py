"""Offline boundaries and failure-path tests; no Docker or DNF is executed."""
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
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p = load('target_host', 'scripts/p1/target_probe.py')
c = load('target_container', 'scripts/p1/target_container_probe.py')


def valid_probe():
    return {'schema': c.SCHEMA, 'scope': 'restricted_probe_container', 'status': 'COLLECTED',
            'errors': [], 'platform': {'os': {'ID': 'centos', 'VERSION_ID': '9',
                                            'PRETTY_NAME': 'CentOS Stream 9'},
                                     'arch': 'x86_64', 'python': '3.9.19', 'uid': 0, 'euid': 0},
            'tools_present': {name: True for name in c.TOOLS},
            'mounts': {'/': {'ro': True}, '/tmp': {'ro': False, 'noexec': True}},
            'dnf': {'status': 'IMPORT_AND_CONFIG_ONLY', 'cacheonly_override': True,
                    'plugins_initialized': False, 'metadata_loaded': False,
                    'versions': {'dnf': '4.14.0', 'rpm': '4.16.1.3'},
                    'repositories': [{'id': 'baseos', 'enabled': True},
                                     {'id': 'crb', 'enabled': False}]}}


class TargetTests(unittest.TestCase):
    def test_config_only_never_initializes_plugins_or_loads_metadata(self):
        base = Mock()
        base.__enter__ = Mock(return_value=base)
        base.__exit__ = Mock(return_value=False)
        base.repos = {'a': SimpleNamespace(id='baseos', enabled=True),
                      'b': SimpleNamespace(id='crb', enabled=False)}
        dnf = SimpleNamespace(__version__='4.14.0', Base=lambda: base)
        rpm = SimpleNamespace(__version__='4.16.1.3')
        result = c.dnf_configuration(lambda name: {'dnf': dnf, 'rpm': rpm}[name])
        base.conf.read.assert_called_once_with()
        base.read_all_repos.assert_called_once_with()
        base.init_plugins.assert_not_called()
        base.fill_sack.assert_not_called()
        base.resolve.assert_not_called()
        base.do_transaction.assert_not_called()
        self.assertTrue(base.conf.cacheonly)
        self.assertEqual(result['repositories'][1], {'id': 'crb', 'enabled': False})

    def test_import_failure_cannot_be_success_and_does_not_disclose_error_text(self):
        with patch.object(c, 'dnf_configuration', side_effect=RuntimeError('SECRET_URL')), \
                patch.object(c, 'os_release', return_value={}), \
                patch.object(c, 'mount_flags', return_value={}), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            c.main()
        result = json.loads(output.getvalue())
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertIn('dnf_UNCONFIRMED', result['errors'])
        self.assertNotIn('SECRET_URL', output.getvalue())

    def test_effective_mount_is_longest_ancestor_not_prefix(self):
        data = ('1 0 0:1 / / ro - overlay overlay rw\n'
                '2 1 0:2 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n'
                '3 1 0:3 / /tmp2 rw - tmpfs tmpfs rw\n')
        self.assertTrue(c.mount_flags(data, '/tmp/build')['noexec'])
        self.assertFalse(c.mount_flags(data, '/tmp2/build')['noexec'])
        self.assertTrue(c.mount_flags(data, '/var')['ro'])

    def test_mount_escape_and_ambiguity(self):
        data = '1 0 0:1 / /work\\040area rw,noexec - tmpfs tmpfs rw\n'
        self.assertTrue(c.mount_flags(data, '/work area/build')['noexec'])
        with self.assertRaises(ValueError):
            c.mount_flags(data + data, '/work area/build')

    def test_valid_observation_is_narrow_success(self):
        self.assertIsNone(p.assess(valid_probe()))

    def test_baseline_crb_missing_import_and_mount_failures_stop(self):
        mutations = [lambda x: x['platform'].update(python='3.9.20'),
                     lambda x: x['dnf']['repositories'][1].update(enabled=True),
                     lambda x: x['dnf'].update(metadata_loaded=True),
                     lambda x: x['tools_present'].update(dnf=False),
                     lambda x: x['mounts']['/tmp'].update(noexec=False),
                     lambda x: x.update(errors=['dnf_UNCONFIRMED']),
                     lambda x: x.update(scope='normal_target')]
        for change in mutations:
            value = valid_probe()
            change(value)
            with self.assertRaises(p.Stop):
                p.assess(value)

    def test_fixed_config_and_restrictions_no_socket_or_bind_mount(self):
        args = p.run_arguments('fixed-name', 'id')
        for word in ('--read-only', '--no-healthcheck', '--pull=never', '-I', '-B'):
            self.assertIn(word, args)
        self.assertEqual(args[args.index('--network') + 1], 'none')
        self.assertEqual(args[args.index('--cap-drop') + 1], 'ALL')
        self.assertEqual(args[-4:], [p.CONFIG, '-I', '-B', '-'])
        self.assertIn(p.CONFIG, args)
        self.assertNotIn('--privileged', args)
        self.assertNotIn('--volume', args)
        self.assertNotIn('--mount', args)
        self.assertNotIn('-v', args)
        self.assertNotIn(':latest', ' '.join(args))

    def test_image_volume_and_identity_changes_stop(self):
        base = {'id': p.CONFIG, 'os': 'linux', 'arch': 'amd64', 'volume_count': 0}
        with patch.object(p, 'command', return_value=json.dumps(base)):
            self.assertEqual(p.inspect_image(time.monotonic() + 10), base)
        for update in ({'volume_count': 1}, {'volume_count': None}, {'id': 'changed'}, {'arch': 'arm64'}):
            with patch.object(p, 'command', return_value=json.dumps(dict(base, **update))):
                with self.assertRaises(p.Stop):
                    p.inspect_image(time.monotonic() + 10)

    def test_command_failures_and_stderr_do_not_disclose_output(self):
        for result in (SimpleNamespace(returncode=1, stdout='SECRET', stderr='SECRET'),
                       SimpleNamespace(returncode=0, stdout='{}', stderr='SECRET')):
            with patch.object(p.subprocess, 'run', return_value=result):
                with self.assertRaises(p.Stop) as raised:
                    p.command(['example'])
                self.assertNotIn('SECRET', str(raised.exception))
        with patch.object(p.subprocess, 'run', side_effect=subprocess.TimeoutExpired('SECRET', 1)):
            with self.assertRaisesRegex(p.Stop, '^COMMAND_TIMEOUT$'):
                p.command(['example'])

    def test_cleanup_rechecks_absence_and_fails_on_residue(self):
        cid = 'a' * 64
        with patch.object(p, 'command', side_effect=[cid, '', '']) as run:
            self.assertTrue(p.cleanup('name', 'id'))
            self.assertEqual(run.call_count, 3)
            self.assertIn('label=ruby-p1.run=id', run.call_args_list[-1].args[0])
        with patch.object(p, 'command', side_effect=[cid, '', cid]):
            self.assertFalse(p.cleanup('name', 'id'))

    def test_without_ci_authorization_no_docker(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True), \
                patch.object(p, 'command') as run, contextlib.redirect_stdout(io.StringIO()):
            out = Path(tmp) / 'evidence.json'
            self.assertEqual(p.main(['--output', str(out)]), 3)
            self.assertEqual(json.loads(out.read_text())['reason'], 'EXPLICIT_EPHEMERAL_CI_REQUIRED')
            run.assert_not_called()

    def test_existing_evidence_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            out = Path(tmp) / 'evidence.json'
            out.write_text('KEEP')
            self.assertEqual(p.main(['--output', str(out)]), 3)
            self.assertEqual(out.read_text(), 'KEEP')

    def run_main(self, cleanup=True, bad_manifest=False, failed_probe=False):
        registry = {'platform_manifest_digest': 'changed' if bad_manifest else p.MANIFEST,
                    'config_digest': p.CONFIG, 'registry_reference': p.TARGET}
        inventory = SimpleNamespace(now=lambda: 'fixture-time',
                                    registry_identity=lambda *a: registry)
        probe = valid_probe()
        if failed_probe:
            probe['errors'] = ['dnf_UNCONFIRMED']
            probe['status'] = 'INCOMPLETE'
        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': p.BRANCH}), \
                patch.object(p.platform, 'system', return_value='Linux'), \
                patch.object(p.platform, 'machine', return_value='x86_64'), \
                patch.object(p.os, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=0)), \
                patch.object(p, 'load_inventory', return_value=inventory), \
                patch.object(p, 'inspect_image', return_value={'volume_count': 0}), \
                patch.object(p, 'command', side_effect=['', json.dumps(probe)]) as run, \
                patch.object(p, 'cleanup', return_value=cleanup) as clean, \
                contextlib.redirect_stdout(io.StringIO()):
            out = Path(tmp) / 'result.json'
            rc = p.main(['--output', str(out), '--allow-pull', '--ephemeral-ci'])
            return rc, json.loads(out.read_text()), run.call_count, clean.call_count

    def test_main_success_does_not_complete_phase1_or_network_validation(self):
        rc, result, _, clean = self.run_main()
        self.assertEqual(rc, 0)
        self.assertEqual(result['status'], p.SUCCESS)
        self.assertFalse(result['p1_02_complete'])
        self.assertFalse(result['repository_access_verified'])
        self.assertFalse(result['normal_target_mounts_verified'])
        self.assertTrue(result['cleanup_confirmed'])
        self.assertEqual(clean, 1)

    def test_cleanup_failure_prevents_pass(self):
        rc, result, _, _ = self.run_main(cleanup=False)
        self.assertEqual(rc, 3)
        self.assertEqual(result['reason'], 'CLEANUP_UNCONFIRMED')

    def test_manifest_failure_prevents_container_start(self):
        rc, result, calls, clean = self.run_main(bad_manifest=True)
        self.assertEqual(rc, 3)
        self.assertEqual(calls, 1)
        self.assertEqual(clean, 0)
        self.assertTrue(result['container_not_started'])

    def test_failed_import_is_retained_without_pass(self):
        rc, result, _, clean = self.run_main(failed_probe=True)
        self.assertEqual(rc, 3)
        self.assertEqual(result['probe']['errors'], ['dnf_UNCONFIRMED'])
        self.assertEqual(clean, 1)


if __name__ == '__main__':
    unittest.main()
