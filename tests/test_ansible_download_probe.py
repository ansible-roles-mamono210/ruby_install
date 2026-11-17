"""Real URI/stat module traffic and strict evidence validation.

The local runtime cannot create AF_UNIX sockets, so these are module subprocess
tests, not a claim that the full playbook/connection/callback path ran locally.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1] / 'scripts/p1'
sys.path.insert(0, str(ROOT))
import ansible_download_probe as host
import ansible_download_controller as controller
import ansible_download_fixture as fixture
import download_guard_fixture as tls

PYTHON = os.environ.get('R49_ANSIBLE_PYTHON', str(Path(sys.executable)))


def module(name, args):
    args = dict(args, _ansible_module_name='ansible.builtin.' + name, _ansible_no_log=True)
    p = subprocess.run([PYTHON, '-B', '-m', 'ansible.modules.' + name],
                       input=json.dumps({'ANSIBLE_MODULE_ARGS': args}), capture_output=True,
                       text=True, timeout=15, check=False)
    if p.stderr.strip() or len(p.stdout.encode()) > 16384:
        raise AssertionError('MODULE_OUTPUT')
    return p.returncode, json.loads(p.stdout)


def measure(redirects='none', count=16):
    cert, key = tls.certificate_material()
    p = subprocess.Popen([sys.executable, '-B', str(ROOT / 'ansible_download_fixture.py')],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    channel = host.Channel(p, time.monotonic() + 120)
    rows = []
    try:
        ready = channel.exchange({'certificate': cert, 'key': key})
        if ready['state'] != 'READY':
            raise AssertionError('READY')
        for index in range(count):
            prepared = channel.exchange({'op': 'prepare', 'index': index})
            v = prepared['variables']
            controller.validate_variables(v)
            args = dict(url=v['p1_url'], dest=v['p1_destination'], method='GET',
                        status_code=[200], follow_redirects=redirects, validate_certs=True,
                        use_proxy=False, use_netrc=False, return_content=False,
                        decompress=False, timeout=5, mode='0600')
            if v['p1_ca']:
                args['ca_path'] = v['p1_ca']
            rc, result = module('uri', args)
            checksum = None
            if rc == 0:
                stat_rc, s = module('stat', dict(path=v['p1_destination'], checksum_algorithm='sha256',
                                               get_checksum=True, get_mime=False, get_attributes=False, follow=False))
                if stat_rc != 0:
                    raise AssertionError('STAT')
                checksum = s['stat']['checksum'] == v['p1_sha256']
            observation = channel.exchange({'op': 'finish', 'index': index})
            rows.append({'index': index, 'module_rc': rc, 'http_status': result.get('status'),
                         'tls_verification_failed': 'CERTIFICATE_VERIFY_FAILED' in result.get('msg', ''),
                         'stat_checksum_matches': checksum, 'observation': observation})
        if count == 16:
            assert channel.exchange({'op': 'stop'}) == {'state': 'FINISHED', 'temporary_directory_removed': True}
    finally:
        p.stdin.close()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait(timeout=5)
        assert p.stderr.read() == b''
        p.stdout.close(); p.stderr.close()
    if count == 16:
        assert p.returncode == 0
    return rows


def expected_result(index):
    case, status, scheme = fixture.MATRIX[index]
    valid, mismatch = case == 'valid', case == 'checksum_mismatch'
    tls_failure = case in ('untrusted_certificate', 'hostname_mismatch')
    events = [{'task': 'P1 uri', 'state': 'ok' if valid or mismatch else 'failed'}]
    if valid or mismatch:
        events += [{'task': 'P1 stat', 'state': 'ok'}, {'task': 'P1 checksum', 'state': 'ok' if valid else 'failed'}]
    events += [{'task': 'P1 gate witness' if valid else 'P1 remember failure stage', 'state': 'ok'},
               {'task': 'P1 publish acquisition result', 'state': 'ok'}]
    return {'schema': 'ruby-p1-ansible-acquisition-events-r49', 'status': 'RECORDED', 'events': events,
            'publication': {'schema': 'ruby-p1-ansible-acquisition-case-r49',
                            'failure_stage': 'none' if valid else 'P1 checksum' if mismatch else 'P1 uri',
                            'http_status': -1 if tls_failure else status, 'uri_failed': not (valid or mismatch),
                            'tls_verification_failed': tls_failure, 'stat_ran': valid or mismatch,
                            'checksum_matches': valid, 'gate_reached': valid}}


class ActualModules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = measure()

    def test_real_uri_stat_matrix(self):
        self.assertEqual(len(self.rows), 16)
        for row in self.rows:
            i = row['index']; case, status, scheme = fixture.MATRIX[i]
            tls_failure = case in ('untrusted_certificate', 'hostname_mismatch')
            self.assertEqual(row['module_rc'], 0 if i < 2 else 1)
            self.assertEqual(row['http_status'], -1 if tls_failure else status)
            self.assertEqual(row['tls_verification_failed'], tls_failure)
            self.assertEqual(row['stat_checksum_matches'], True if i == 0 else False if i == 1 else None)
            o = row['observation']
            self.assertEqual(o['sink_delta'], {s: {'connections': 0, 'requests': 0} for s in ('http', 'https')})
            self.assertEqual(o['origin_connections'], 1)
            self.assertEqual(o['origin_requests'], 0 if tls_failure else 1)
            self.assertEqual(o['file_exists'], i < 2)
            # Full playbook's gate intentionally did not run in module-only tests.
            self.assertFalse(o['gate_marker'])

    def test_validator_rejects_order_type_missing_and_extra_evidence(self):
        for row in self.rows:
            i = row['index']
            good = expected_result(i)
            observation = copy.deepcopy(row['observation'])
            observation['gate_marker'] = i == 0  # synthetic callback/gate unit fixture only
            host.validate_case(i, good, observation)
            for mutation in ('order', 'secret_field', 'missing_stat', 'wrong_tls', 'boolean_counter', 'forbidden_contact', 'checksum_bypass'):
                with self.subTest(index=i, mutation=mutation):
                    r, o = copy.deepcopy(good), copy.deepcopy(observation)
                    if mutation == 'order': r['events'].reverse()
                    if mutation == 'secret_field': r['raw_stderr'] = 'not-a-secret'
                    if mutation == 'missing_stat': r['publication']['stat_ran'] = not r['publication']['stat_ran']
                    if mutation == 'wrong_tls': r['publication']['tls_verification_failed'] = not r['publication']['tls_verification_failed']
                    if mutation == 'boolean_counter': o['origin_connections'] = True
                    if mutation == 'forbidden_contact': o['sink_delta']['http']['connections'] = 1
                    if mutation == 'checksum_bypass': o['gate_marker'] = not o['gate_marker']
                    with self.assertRaises(host.Stop): host.validate_case(i, r, o)

    def test_follow_redirects_regression_reaches_sink(self):
        rows = measure(redirects='all', count=4)
        # 301 follows the sink with real module traffic (300 need not redirect).
        o = rows[3]['observation']
        self.assertGreater(o['sink_delta']['http']['connections'], 0)
        with self.assertRaises(host.Stop): host.validate_case(3, expected_result(3), o)

    def test_evidence_has_no_tls_material(self):
        s = json.dumps(self.rows)
        self.assertNotIn('PRIVATE KEY', s)
        self.assertNotIn('BEGIN CERTIFICATE', s)


class InputBoundaries(unittest.TestCase):
    def test_no_response_times_out_without_repeating_request(self):
        p=Mock()
        c=host.Channel(p,time.monotonic()+1)
        with patch.object(host.select,'select',return_value=([],[],[])):
            with self.assertRaisesRegex(host.Stop,'FIXTURE_TIMEOUT'):c.exchange({'op':'stop'})
        self.assertEqual(p.stdin.write.call_count,1)

    def test_fixed_isolated_target_and_controller_boundary(self):
        runtime=host.load('runtime_smoke')
        target=host.target_args(runtime,'target-name','run-id')
        control=host.controller_args(runtime,'controller-name','run-id',Path('/tmp/owned'),'123')
        for args in (target,control):
            for flag,value in [('--network','none'),('--cap-drop','ALL'),('--security-opt','no-new-privileges')]:
                self.assertEqual(args[args.index(flag)+1],value)
            self.assertIn('--read-only',args)
            self.assertNotIn('--privileged',args)
        self.assertNotIn('--mount',target)
        self.assertEqual(target[target.index('--user')+1],'65534:65534')
        mounts=[control[i+1] for i,v in enumerate(control) if v=='--mount']
        self.assertEqual(len(mounts),2)
        self.assertTrue(all(v.endswith('readonly') for v in mounts))

    def test_callback_hides_invalid_publication(self):
        spec=importlib.util.spec_from_file_location('r49_callback',ROOT/'ansible_download_callback.py')
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        result=Mock();result.task_name='P1 publish acquisition result'
        result.host.get_name.return_value='target';result.warnings=[];result.deprecations=[]
        result.task.no_log=False;result.result={'msg':{'private_key':'fixture-string'}}
        c=m.CallbackModule();c.record(result,'ok')
        self.assertTrue(c.invalid);self.assertIsNone(c.publication)

    def test_checksum_failure_event_is_retained_without_exposing_result(self):
        spec=importlib.util.spec_from_file_location('r49_callback',ROOT/'ansible_download_callback.py')
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        result=Mock();result.task_name='P1 checksum';result.host.get_name.return_value='target'
        result.warnings=[];result.deprecations=[];result.task.no_log=True
        result.result={'private_key':'fixture-string'}
        c=m.CallbackModule();c.record(result,'failed')
        self.assertFalse(c.invalid)
        self.assertEqual(c.events,[{'task':'P1 checksum','state':'failed'}])

    def test_input_scope_rejects_external_urls_and_unowned_paths(self):
        v = dict(p1_url='https://localhost:1234/source', p1_destination='/tmp/ruby-p1-ansible-abcd/case-0/source.tar.gz',
                 p1_sha256='a'*64, p1_ca='/tmp/ruby-p1-ansible-abcd/cert.pem')
        controller.validate_variables(v)
        for key, value in [('p1_url','http://localhost:1234/source'), ('p1_url','https://example.com/source'),
                           ('p1_destination','/etc/ruby'), ('p1_ca','/etc/secret'), ('p1_sha256',True)]:
            bad=dict(v);bad[key]=value
            with self.assertRaises(ValueError):controller.validate_variables(bad)

    def test_gate_requires_explicit_ci_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'result.json'
            code=host.main(['--output',str(output)])
            self.assertEqual(code,3)
            value=json.loads(output.read_text())
            self.assertEqual(value['reason'],'EXPLICIT_EPHEMERAL_CI_REQUIRED')
            self.assertEqual(value['cleanup'],{})


if __name__ == '__main__':
    unittest.main()
