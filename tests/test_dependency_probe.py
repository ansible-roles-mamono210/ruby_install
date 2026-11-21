"""Offline DNF boundary tests; the DNF API itself is verified only in the planned CI."""
import contextlib
import copy
import ctypes
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
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


class Substitutions(dict):
    def __init__(self):
        super().__init__(releasever='9', arch='x86_64', basearch='x86_64')
        self.update_from_etc = Mock(side_effect=lambda *a, **kw: self.update(stream='9-stream'))


def configuration(**changes):
    result = SimpleNamespace(read=Mock(), sslverify=True, gpgcheck=True, proxy='',
                             baseurl=[], metalink='', mirrorlist='', installroot='/',
                             varsdir=['/etc/yum/vars/', '/etc/dnf/vars/'],
                             substitutions=Substitutions())
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
                           const=SimpleNamespace(TMPDIR='/var/tmp/'),
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


def trace_state():
    return {'stage': 'identity', 'condition': 'none', 'package': 'none',
            'failure': None, 'state_check': 'NOT_STARTED'}


def failure_report():
    return {'schema': w.SCHEMA, 'status': 'INCOMPLETE', 'stage': 'metadata_and_solver',
            'reason': 'DEPENDENCY_API_OR_METADATA_ERROR', 'diagnostic': {
                'stage': 'metadata_load', 'condition': 'crb_off', 'package': 'none',
                'reason': 'DEPENDENCY_API_OR_METADATA_ERROR', 'exception_kind': 'OS_ERROR',
                'errno': 'EROFS', 'state_check': 'MATCH',
                'error_chain': w.error_chain(OSError(errno.EROFS, 'SECRET')),
                'versions': {'dnf': '4.14.0', 'rpm': '4.16.1.3'},
                'substitutions': w.empty_substitutions()}}


def raised_in(module, name, error, inner=None):
    namespace = {'__name__': module, 'error': error, 'inner': inner}
    body = 'inner()' if inner is not None else 'raise error'
    exec(compile('def ' + name + '():\n    ' + body + '\n', '/PRIVATE_SOURCE', 'exec'), namespace)
    return namespace[name]


class ErrorChainTests(unittest.TestCase):
    def test_known_dnf_kinds_and_unknown_names_never_stringify(self):
        def forbidden(_self):
            raise AssertionError('must not stringify')
        for name, expected in w.DNF_ERROR_NAMES.items():
            cls = type(name, (Exception,), {'__module__': 'dnf.exceptions', '__str__': forbidden})
            item = w.error_chain(cls('PRIVATE_MESSAGE'))['items'][0]
            self.assertEqual(item['kind'], expected)
            self.assertNotIn('PRIVATE', json.dumps(item))
        for module, name in [('PRIVATE_MODULE', 'RepoError'), ('dnf.exceptions', 'PRIVATE_CLASS')]:
            cls = type(name, (Exception,), {'__module__': module, '__str__': forbidden})
            self.assertEqual(w.error_chain(cls('PRIVATE'))['items'][0]['kind'], 'OTHER')
        cls = type('Error', (Exception,), {'__module__': 'libdnf.error'})
        self.assertEqual(w.error_chain(cls('PRIVATE'))['items'][0]['kind'], 'LIBDNF_ERROR')

    def test_deepest_allowlisted_frame_and_unknown_module_are_distinct(self):
        cases = [('dnf.repo', 'load', 'REPOSITORY_LOAD'),
                 ('dnf.sack', '_build_sack', 'SACK_CREATE'),
                 ('dnf.lock', '_try_lock', 'LOCK_ACQUIRE'),
                 ('PRIVATE_MODULE', 'load', 'UNMAPPED'),
                 ('dnf.repo', 'PRIVATE_FUNCTION', 'UNMAPPED')]
        for module, name, expected in cases:
            inner = raised_in(module, name, RuntimeError('PRIVATE_MESSAGE'))
            outer = raised_in('dnf.base', 'fill_sack', None, inner)
            try:
                outer()
            except RuntimeError as error:
                value = w.error_chain(error)
            self.assertEqual(value['items'][0]['frame'],
                             'FILL_SACK' if expected == 'UNMAPPED' else expected)
            self.assertEqual(value['items'][0]['frames'], 'COMPLETE')
            self.assertNotIn('PRIVATE', json.dumps(value))

    def test_implicit_context_keeps_os_errno_without_claiming_cause(self):
        cls = type('RepoError', (Exception,), {'__module__': 'dnf.exceptions'})
        try:
            try:
                raise PermissionError(errno.EACCES, 'PRIVATE_URL', '/PRIVATE_PATH')
            except PermissionError:
                raise cls('PRIVATE_WRAP')
        except cls as error:
            value = w.error_chain(error)
        self.assertEqual([(x['link'], x['kind'], x['errno']) for x in value['items']],
                         [('SELF', 'DNF_REPO_ERROR', 'NONE'),
                          ('CONTEXT', 'PERMISSION_ERROR', 'EACCES')])
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_explicit_cause_takes_precedence_over_context(self):
        outer = RuntimeError('PRIVATE')
        outer.__cause__ = OSError(errno.EROFS, 'PRIVATE_CAUSE')
        outer.__context__ = ValueError('PRIVATE_CONTEXT')
        value = w.error_chain(outer)
        self.assertEqual([(x['link'], x['errno']) for x in value['items']],
                         [('SELF', 'NONE'), ('CAUSE', 'EROFS')])

    def test_suppressed_context_is_not_followed(self):
        outer = RuntimeError('PRIVATE')
        outer.__context__ = OSError(errno.EACCES, 'PRIVATE')
        outer.__suppress_context__ = True
        self.assertEqual(len(w.error_chain(outer)['items']), 1)

    def test_cycle_and_chain_limit_are_bounded_and_reported(self):
        a, b = RuntimeError('PRIVATE'), ValueError('PRIVATE')
        a.__cause__, b.__cause__ = b, a
        value = w.error_chain(a)
        self.assertEqual((value['state'], len(value['items'])), ('CYCLE', 2))
        chain = [RuntimeError('PRIVATE') for _ in range(6)]
        for left, right in zip(chain, chain[1:]):
            left.__cause__ = right
        value = w.error_chain(chain[0])
        self.assertEqual((value['state'], len(value['items'])), ('LIMIT', 4))

    def test_frame_walk_has_a_fixed_bound(self):
        def recurse(n):
            if n:
                recurse(n - 1)
            else:
                raise RuntimeError('PRIVATE')
        try:
            recurse(70)
        except RuntimeError as error:
            value = w.error_chain(error)
        self.assertEqual(value['items'][0]['frames'], 'LIMIT')
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_non_string_module_metadata_is_not_exported_or_used_as_a_key(self):
        fn = raised_in(['PRIVATE_MODULE'], 'load', ValueError('PRIVATE'))
        try:
            fn()
        except ValueError as error:
            value = w.error_chain(error)
        self.assertEqual(value['items'][0]['frame'], 'UNMAPPED')

    def test_parser_accepts_diagnostics_only_as_failure(self):
        value = failure_report()
        value['diagnostic']['error_chain']['items'][0].update(
            kind='DNF_REPO_ERROR', errno='NONE', frame='REPOSITORY_LOAD',
            message={'state': 'UNMAPPED', 'repository': 'NONE', 'signals': []})
        summary = h.failure_summary(json.dumps(value), w)
        self.assertEqual(summary['state'], 'VALIDATED_FAILURE_ONLY')
        self.assertEqual(summary['diagnostic']['error_chain'], value['diagnostic']['error_chain'])
        with self.assertRaises(h.Stop):
            h.validate(value, w)

    def test_parser_rejects_malformed_chain_and_extra_or_unbounded_content(self):
        mutations = [lambda c: c.update(state='PRIVATE'), lambda c: c.update(items=[]),
                     lambda c: c.update(items=c['items'] * 5), lambda c: c.update(message='PRIVATE'),
                     lambda c: c.update(state='LIMIT'),
                     lambda c: c['items'][0].update(kind='PRIVATE'),
                     lambda c: c['items'][0].update(errno=13),
                     lambda c: c['items'][0].update(frame='PRIVATE'),
                     lambda c: c['items'][0].update(frames=True),
                     lambda c: c['items'][0].update(link='CAUSE'),
                     lambda c: c['items'][0].update(path='/PRIVATE'),
                     lambda c: c['items'].append(dict(c['items'][0]))]
        for mutate in mutations:
            value = failure_report()
            mutate(value['diagnostic']['error_chain'])
            self.assertEqual(h.failure_summary(json.dumps(value), w), {'state': 'INVALID_SCHEMA'})
        for invalid in (None, [], 'PRIVATE'):
            value = failure_report()
            value['diagnostic']['error_chain'] = invalid
            self.assertEqual(h.failure_summary(json.dumps(value), w), {'state': 'INVALID_SCHEMA'})

    def test_parser_rejects_nested_duplicate_keys(self):
        value = json.dumps(failure_report()).replace('"link":', '"link":"PRIVATE","link":', 1)
        self.assertEqual(h.failure_summary(value, w), {'state': 'INVALID_JSON'})


class NativeMessageTests(unittest.TestCase):
    @staticmethod
    def native(message):
        # Same CPython API/name used by the verified SWIG error.i source.
        create = ctypes.pythonapi.PyErr_NewException
        create.argtypes = [ctypes.c_char_p, ctypes.py_object, ctypes.py_object]
        create.restype = ctypes.py_object
        cls = create(b'libdnf._error.Error', Exception, {})
        return cls(message)

    def test_actual_cpython_native_exception_name_is_recognized(self):
        error = self.native('PRIVATE')
        self.assertEqual(type(error).__module__, 'libdnf._error')
        item = w.error_chain(error)['items'][0]
        self.assertEqual(item['kind'], 'LIBDNF_ERROR')
        self.assertEqual(item['message'], {'state': 'UNMAPPED', 'repository': 'NONE', 'signals': []})

    def test_download_wrapper_separates_repo_dns_and_tls_without_exporting_text(self):
        for repo, code, expected in [('baseos', 6, 'CURL_DNS'),
                                     ('appstream', 60, 'CURL_TLS_VERIFY'),
                                     ('crb', 77, 'CURL_CA_FILE'),
                                     ('PRIVATE_REPO', 7, 'CURL_CONNECT')]:
            text = (f"Failed to download metadata for repo '{repo}': "
                    f'Cannot prepare internal mirrorlist: Curl error ({code}): '
                    'PRIVATE_DETAIL for https://PRIVATE_USER:PRIVATE_PASSWORD@private.invalid/PRIVATE '
                    '[PRIVATE_TOKEN]')
            item = w.error_chain(self.native(text))['items'][0]['message']
            self.assertEqual(item['repository'], repo if repo in w.REPOS else 'OTHER')
            self.assertEqual(set(item['signals']), {'METADATA_DOWNLOAD', 'MIRRORLIST_PREPARE', expected})
            self.assertNotIn('PRIVATE', json.dumps(item))
            self.assertNotIn('private.invalid', json.dumps(item))

    def test_curl_code_clues_remain_distinct_and_unknown_codes_are_not_echoed(self):
        for code, expected in [('5', 'CURL_PROXY_DNS'), ('22', 'CURL_HTTP'),
                ('23', 'CURL_WRITE'), ('26', 'CURL_READ'), ('27', 'CURL_MEMORY'),
                ('28', 'CURL_TIMEOUT'), ('35', 'CURL_TLS_CONNECT'), ('47', 'CURL_REDIRECT_LIMIT'),
                ('55', 'CURL_SEND'), ('56', 'CURL_RECEIVE'), ('999', 'CURL_OTHER')]:
            item = w.error_chain(self.native(f'Curl error ({code}): PRIVATE'))['items'][0]['message']
            self.assertEqual(item['signals'], [expected])

    def test_http_status_is_separate_from_filesystem_permissions(self):
        for code, expected in [('401', 'HTTP_401'), ('403', 'HTTP_403'), ('404', 'HTTP_404'),
                               ('429', 'HTTP_429'), ('503', 'HTTP_5XX'), ('418', 'HTTP_OTHER')]:
            item = w.error_chain(self.native('Status code: ' + code + ' for https://PRIVATE'))['items'][0]
            self.assertEqual(item['message']['signals'], [expected])
            self.assertEqual(item['errno'], 'NONE')

    def test_directory_failures_keep_operation_and_os_text_as_clues_only(self):
        cases = [('repo temporary directory', 'Read-only file system', 'REPO_TEMP_CREATE', 'FS_READ_ONLY'),
                 ('repo destination directory', 'Permission denied', 'REPO_DEST_CREATE', 'FS_PERMISSION'),
                 ('persistdir', 'No space left on device', 'REPO_PERSIST_CREATE', 'FS_NO_SPACE'),
                 ('directory', 'No such file or directory', 'REPO_DIR_CREATE', 'FS_MISSING')]
        for operation, phrase, a, b in cases:
            item = w.error_chain(self.native(f'Cannot create {operation} "/PRIVATE/PATH": {phrase}'))['items'][0]
            self.assertEqual(item['message']['signals'], sorted([a, b]))
            self.assertEqual(item['errno'], 'NONE')
            self.assertNotIn('PRIVATE', json.dumps(item))

    def test_urls_and_paths_are_not_searched_for_error_keywords(self):
        texts = ['https://private.invalid/Curl error (60): fake',
                 'Unknown error: Status code: 403 for PRIVATE',
                 'Cannot create directory "/PRIVATE/Permission denied": Unmapped error',
                 'Unrecognized translation: Curl error (6): PRIVATE']
        for text in texts:
            item = w.error_chain(self.native(text))['items'][0]['message']
            self.assertEqual(item['state'], 'UNMAPPED')
            self.assertEqual(item['signals'], [])

    def test_known_message_limit_has_no_truncated_or_silent_positive_match(self):
        prefix = 'Curl error (6): '
        for size, state in [(4096, 'MATCHED'), (4097, 'LIMIT')]:
            item = w.error_chain(self.native(prefix + 'x' * (size - len(prefix))))['items'][0]['message']
            self.assertEqual(item['state'], state)
            if state == 'LIMIT':
                self.assertEqual(item['signals'], [])

    def test_objects_and_custom_formatters_are_never_invoked(self):
        def forbidden(*_):
            raise AssertionError('must not read text through custom methods')
        dangerous = type('Dangerous', (), {'__str__': forbidden, '__repr__': forbidden})()
        cls = type('RepoError', (Exception,), {'__module__': 'dnf.exceptions',
                    '__str__': forbidden, '__repr__': forbidden, 'args': property(forbidden)})
        for arg in (dangerous, ['PRIVATE'], 6):
            self.assertEqual(w.error_chain(cls(arg))['items'][0]['message']['state'], 'NO_TEXT')
        item = w.error_chain(cls('Curl error (6): PRIVATE'))['items'][0]
        self.assertEqual(item['message']['signals'], ['CURL_DNS'])
        self.assertNotIn('PRIVATE', json.dumps(item))

    def test_non_native_exceptions_do_not_gain_text_based_classification(self):
        for error in (RuntimeError('Curl error (6): PRIVATE'),
                      Exception('Status code: 403 for PRIVATE')):
            self.assertEqual(w.error_chain(error)['items'][0]['message']['state'], 'NOT_APPLICABLE')

    def test_dnf_value_storage_works_with_empty_args_and_no_context(self):
        def forbidden(*_):
            raise AssertionError('must not invoke formatter or descriptor')
        cls = type('RepoError', (Exception,), {'__module__': 'dnf.exceptions',
                    '__str__': forbidden, '__repr__': forbidden, 'value': property(forbidden)})
        error = cls()
        BaseException.__dict__['__dict__'].__get__(error)['value'] = 'Curl error (28): PRIVATE'
        self.assertEqual(error.args, ())
        item = w.error_chain(error)['items'][0]
        self.assertEqual(item['message']['signals'], ['CURL_TIMEOUT'])
        BaseException.__dict__['__dict__'].__get__(error)['value'] = object()
        self.assertEqual(w.error_chain(error)['items'][0]['message']['state'], 'NO_TEXT')

    def test_version_information_is_bounded_numeric_or_unknown(self):
        for value in ('4.14.0', '4.16.1.3'):
            self.assertEqual(w.version_code(value), value)
        for value in (None, 4.14, True, 'PRIVATE', '4.14.0-PRIVATE', '4.' + '1' * 10000):
            self.assertEqual(w.version_code(value), 'UNKNOWN')

    def test_native_failure_roundtrips_as_failure_not_success(self):
        value = failure_report()
        value['diagnostic']['error_chain'] = w.error_chain(self.native(
            "Failed to download metadata for repo 'baseos': Curl error (6): PRIVATE"))
        result = h.failure_summary(json.dumps(value), w)
        self.assertEqual(result['state'], 'VALIDATED_FAILURE_ONLY')
        self.assertEqual(result['diagnostic']['versions'], value['diagnostic']['versions'])
        with self.assertRaises(h.Stop):
            h.validate(value, w)

    def test_host_rejects_message_payloads_bad_types_and_inconsistent_states(self):
        mutations = [lambda m: m.update(text='PRIVATE'), lambda m: m.update(repository='PRIVATE'),
            lambda m: m.update(signals=['PRIVATE']), lambda m: m.update(signals=[{}]),
            lambda m: m.update(signals=['CURL_DNS', 'CURL_DNS']), lambda m: m.update(signals=[]),
            lambda m: m.update(signals=list(sorted(w.MESSAGE_SIGNALS))[:6]),
            lambda m: m.update(state='NOT_APPLICABLE'), lambda m: m.update(state='LIMIT'),
            lambda m: m.update(state=True), lambda m: m.update(repository='baseos')]
        for mutate in mutations:
            value = failure_report()
            value['diagnostic']['error_chain'] = w.error_chain(self.native('Curl error (6): PRIVATE'))
            mutate(value['diagnostic']['error_chain']['items'][0]['message'])
            self.assertEqual(h.failure_summary(json.dumps(value), w), {'state': 'INVALID_SCHEMA'})
        for bad in (None, {}, {'dnf': 'PRIVATE', 'rpm': '4.0'}, {'dnf': True, 'rpm': '4.0'},
                    {'dnf': '4.0', 'rpm': '4.0', 'path': 'PRIVATE'}):
            value = failure_report()
            value['diagnostic']['versions'] = bad
            self.assertEqual(h.failure_summary(json.dumps(value), w), {'state': 'INVALID_SCHEMA'})

    def test_four_native_items_stay_below_host_size_limit(self):
        items = [self.native("Failed to download metadata for repo 'baseos': "
                            'Cannot prepare internal mirrorlist: Curl error (60): PRIVATE') for _ in range(4)]
        for left, right in zip(items, items[1:]):
            left.__cause__ = right
        value = failure_report()
        value['diagnostic']['error_chain'] = w.error_chain(items[0])
        payload = json.dumps(value)
        self.assertLess(len(payload.encode()), 8192)
        self.assertNotIn('PRIVATE', payload)
        self.assertEqual(h.failure_summary(payload, w)['state'], 'VALIDATED_FAILURE_ONLY')


class TemporaryRootTests(unittest.TestCase):
    def test_base_constructor_and_close_share_private_cache_root(self):
        events = []
        class ClosingBase(Base):
            def __exit__(self, *args):
                events.append(('close', dnf.const.TMPDIR))
        base = ClosingBase()
        dnf = fake_dnf(base)
        def construct():
            path = Path(dnf.const.TMPDIR)
            self.assertEqual(path.parent, Path(directory))
            self.assertEqual(path.name, 'dnf-bootstrap')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            events.append(('construct', str(path)))
            return base
        dnf.Base = Mock(side_effect=construct)
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(w.condition(dnf, directory, True)['resolution'], 'RESOLVED')
        self.assertEqual([e[0] for e in events], ['construct', 'close'])
        self.assertEqual(events[0][1], events[1][1])
        self.assertEqual(dnf.const.TMPDIR, '/var/tmp/')
        self.assertFalse(Path(events[0][1]).exists())

    def test_constructor_failure_restores_constant_and_preserves_diagnostic(self):
        class DnfError(Exception):
            pass
        dnf, trace = fake_dnf(Base()), trace_state()
        dnf.Base = Mock(side_effect=DnfError('SECRET'))
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(w, 'rpm_state', return_value={'count': 1}), \
                patch.object(w, 'configuration_state', return_value={'count': 1}), \
                self.assertRaises(DnfError):
            w.measure(dnf, SimpleNamespace(), directory, trace)
        self.assertEqual(dnf.const.TMPDIR, '/var/tmp/')
        self.assertEqual(trace['failure']['stage'], 'base_open')
        self.assertEqual(trace['failure']['condition'], 'crb_off')
        self.assertEqual(trace['state_check'], 'MATCH')
        self.assertNotIn('SECRET', json.dumps(trace))
        dnf.Base.assert_called_once_with()

    def test_metadata_failure_closes_before_restoration(self):
        roots = []
        class ClosingBase(Base):
            def __exit__(self, *args):
                roots.append(dnf.const.TMPDIR)
        base = ClosingBase()
        base.fill_sack = Mock(side_effect=RuntimeError('SECRET'))
        dnf = fake_dnf(base)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                w.condition(dnf, directory, False)
            self.assertEqual(roots, [str(Path(directory) / 'dnf-bootstrap')])
        self.assertEqual(dnf.const.TMPDIR, '/var/tmp/')

    def test_close_failure_still_restores_constant(self):
        class BadClose(Base):
            def __exit__(self, *args):
                raise OSError(errno.EIO, 'SECRET')
        dnf = fake_dnf(BadClose())
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(OSError):
            w.condition(dnf, directory, True)
        self.assertEqual(dnf.const.TMPDIR, '/var/tmp/')

    def test_unexpected_default_stops_before_directory_or_base_creation(self):
        for value in ('/tmp', '/SECRET', '', None, 1):
            dnf = fake_dnf(Base())
            dnf.const.TMPDIR = value
            dnf.Base = Mock()
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(w.Stop, '^DNF_TEMP_ROOT_UNEXPECTED$'):
                    w.condition(dnf, directory, True)
                self.assertEqual(list(Path(directory).iterdir()), [])
            dnf.Base.assert_not_called()
            self.assertEqual(dnf.const.TMPDIR, value)

    def test_directory_failure_stops_before_base_and_leaves_constant(self):
        dnf = fake_dnf(Base())
        dnf.Base = Mock()
        with patch.object(w.Path, 'mkdir', side_effect=PermissionError(errno.EACCES, 'SECRET')), \
                self.assertRaises(PermissionError):
            w.condition(dnf, '/tmp/not-created', True)
        dnf.Base.assert_not_called()
        self.assertEqual(dnf.const.TMPDIR, '/var/tmp/')

    def test_conditions_use_distinct_roots_and_restore_exact_original(self):
        dnf = fake_dnf(Base())
        dnf.const.TMPDIR = '/var/tmp'
        roots = []
        def construct():
            roots.append(dnf.const.TMPDIR)
            return Base()
        dnf.Base = construct
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(w, 'rpm_state', return_value={'count': 1}), \
                patch.object(w, 'configuration_state', return_value={'count': 1}):
            value = w.measure(dnf, SimpleNamespace(__version__='4.16.1.3'), directory)
            self.assertTrue(value['system_state_unchanged'])
            self.assertEqual(roots, [str(Path(directory) / c / 'dnf-bootstrap')
                                     for c in ('crb-off', 'crb-on')])
            self.assertEqual(dnf.const.TMPDIR, '/var/tmp')


class DiagnosticTests(unittest.TestCase):
    def test_exception_messages_filenames_and_unknown_class_names_are_not_serialized(self):
        class SECRET_EXCEPTION(Exception):
            pass
        cases = [(PermissionError(errno.EACCES, 'SECRET', '/SECRET'), 'PERMISSION_ERROR', 'EACCES'),
                 (OSError(errno.EROFS, 'SECRET', '/SECRET'), 'OS_ERROR', 'EROFS'),
                 (ModuleNotFoundError('SECRET'), 'MODULE_NOT_FOUND', 'NONE'),
                 (AttributeError('SECRET'), 'ATTRIBUTE_ERROR', 'NONE'),
                 (TypeError('SECRET'), 'TYPE_ERROR', 'NONE'),
                 (ValueError('SECRET'), 'VALUE_ERROR', 'NONE'),
                 (SECRET_EXCEPTION('SECRET'), 'OTHER', 'NONE'),
                 (w.Stop('SECRET'), 'STOP', 'NONE')]
        for error, kind, code in cases:
            t = trace_state()
            w.remember_failure(t, error)
            self.assertEqual((t['failure']['exception_kind'], t['failure']['errno']), (kind, code))
            self.assertNotIn('SECRET', json.dumps(t))

    def test_metadata_error_preserves_original_stage_after_state_checks(self):
        base, t = Base(), trace_state()
        base.fill_sack = Mock(side_effect=OSError(errno.EROFS, 'SECRET'))
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(w, 'rpm_state', return_value={'count': 1}), \
                patch.object(w, 'configuration_state', return_value={'count': 1}), \
                self.assertRaises(OSError):
            w.measure(fake_dnf(base), SimpleNamespace(), directory, t)
        self.assertEqual(t['failure']['stage'], 'metadata_load')
        self.assertEqual(t['failure']['condition'], 'crb_off')
        self.assertEqual(t['failure']['errno'], 'EROFS')
        self.assertEqual(t['state_check'], 'MATCH')
        self.assertNotIn('SECRET', json.dumps(t))

    def test_state_check_error_does_not_erase_first_failure(self):
        for change in ('error', 'changed'):
            base, t = Base(), trace_state()
            base.fill_sack = Mock(side_effect=AttributeError('SECRET_PRIMARY'))
            after = OSError(errno.EACCES, 'SECRET_SECONDARY') if change == 'error' else {'count': 2}
            with tempfile.TemporaryDirectory() as directory, \
                    patch.object(w, 'rpm_state', side_effect=[{'count': 1}, after]), \
                    patch.object(w, 'configuration_state', return_value={'count': 1}), \
                    self.assertRaises(OSError if change == 'error' else w.Stop):
                w.measure(fake_dnf(base), SimpleNamespace(), directory, t)
            self.assertEqual(t['failure']['stage'], 'metadata_load')
            self.assertEqual(t['failure']['exception_kind'], 'ATTRIBUTE_ERROR')
            self.assertEqual(t['state_check'], 'ERROR' if change == 'error' else 'CHANGED')
            self.assertNotIn('SECRET', json.dumps(t))

    def test_configuration_and_package_query_failures_have_distinct_checkpoints(self):
        for which in ('configuration', 'query'):
            base, t = Base(), trace_state()
            if which == 'configuration':
                base.conf.read.side_effect = AttributeError('SECRET')
            else:
                base.fill_sack = lambda **kw: setattr(base, 'sack', SimpleNamespace(
                    query=Mock(side_effect=TypeError('SECRET'))))
            with tempfile.TemporaryDirectory() as directory, \
                    patch.object(w, 'rpm_state', return_value={'count': 1}), \
                    patch.object(w, 'configuration_state', return_value={'count': 1}), \
                    self.assertRaises(AttributeError if which == 'configuration' else TypeError):
                w.measure(fake_dnf(base), SimpleNamespace(), directory, t)
            self.assertEqual(t['failure']['stage'], 'configuration_read' if which == 'configuration'
                             else 'candidate_query')
            self.assertEqual(t['failure']['package'], 'none' if which == 'configuration' else 'gcc')

    def test_worker_main_emits_enum_report_and_cancels_alarm_on_failure(self):
        output = io.StringIO()
        fake = SimpleNamespace(__version__='4.14.0')
        with patch.dict(os.environ, {'RUBY_P1_DEPENDENCY_PROBE': '1'}, clear=True), \
                patch.object(w.os, 'getuid', return_value=65534), \
                patch.object(w.platform, 'system', return_value='Linux'), \
                patch.object(w.platform, 'machine', return_value='x86_64'), \
                patch.object(w.platform, 'python_version', return_value='3.9.19'), \
                patch.object(w.Path, 'read_text', return_value='ID="centos"\nVERSION_ID="9"\n'), \
                patch.dict(sys.modules, {'dnf': fake, 'rpm': SimpleNamespace()}), \
                patch.object(w, 'rpm_state', side_effect=PermissionError(errno.EACCES, 'SECRET')), \
                patch.object(w, 'silent_dependencies', side_effect=contextlib.nullcontext), \
                patch.object(w.signal, 'signal'), patch.object(w.signal, 'alarm') as alarm, \
                contextlib.redirect_stdout(output):
            rc = w.main()
        value = json.loads(output.getvalue())
        self.assertEqual(rc, 3)
        self.assertEqual(value['diagnostic']['stage'], 'rpm_before')
        self.assertEqual(value['diagnostic']['state_check'], 'NOT_STARTED')
        self.assertEqual(value['diagnostic']['errno'], 'EACCES')
        self.assertEqual([c.args[0] for c in alarm.call_args_list], [510, 0])
        self.assertEqual(h.failure_summary(output.getvalue(), w)['state'], 'VALIDATED_FAILURE_ONLY')
        self.assertNotIn('SECRET', output.getvalue())

    def test_native_output_suppression_is_unchanged_in_local_subprocess(self):
        code = ('import importlib.util,os\n'
                's=importlib.util.spec_from_file_location("worker",' + repr(str(ROOT / 'scripts/p1/dependency_container_probe.py')) + ')\n'
                'w=importlib.util.module_from_spec(s);s.loader.exec_module(w)\n'
                'with w.silent_dependencies():\n'
                ' os.write(1,b"PRIVATE_STDOUT");os.write(2,b"PRIVATE_STDERR")\n'
                'print("RESTORED")\n')
        proc = subprocess.run([sys.executable, '-I', '-B', '-c', code], capture_output=True,
                              text=True, timeout=10, check=True)
        self.assertEqual(proc.stdout, 'RESTORED\n')
        self.assertEqual(proc.stderr, '')

    def test_failure_parser_rejects_extra_fields_unknown_enums_and_wrong_types(self):
        mutations = [lambda v: v.update(detail='SECRET'),
                     lambda v: v.update(schema='OLD'),
                     lambda v: v.update(reason='SECRET'),
                     lambda v: v.update(stage=['SECRET']),
                     lambda v: v['diagnostic'].update(path='/SECRET'),
                     lambda v: v['diagnostic'].update(stage='SECRET'),
                     lambda v: v['diagnostic'].update(package='SECRET'),
                     lambda v: v['diagnostic'].update(exception_kind='SECRET'),
                     lambda v: v['diagnostic'].update(errno=13),
                     lambda v: v['diagnostic'].update(state_check=True)]
        for mutation in mutations:
            value = failure_report()
            mutation(value)
            self.assertEqual(h.failure_summary(json.dumps(value), w), {'state': 'INVALID_SCHEMA'})

    def test_failure_parser_rejects_duplicate_trailing_oversize_and_non_json(self):
        original = json.dumps(failure_report())
        values = [original.replace('"schema":', '"schema":"SECRET","schema":', 1),
                  original + 'SECRET', '{"status":', 'SECRET', '[' * 2000, ' ' * 8193]
        for value in values:
            self.assertIn(h.failure_summary(value, w)['state'], ('INVALID_JSON', 'TOO_LARGE'))
            self.assertNotIn('SECRET', json.dumps(h.failure_summary(value, w)))


class SubstitutionTests(unittest.TestCase):
    def test_configured_root_and_varsdir_loaded_before_repositories(self):
        base, order = Base(), []
        def read_conf():
            order.append('config')
            base.conf.installroot = '/configured-root'
            base.conf.varsdir = ['/configured-vars']
        def load_vars(root, *, varsdir):
            order.append('variables')
            self.assertEqual((root, varsdir), ('/configured-root', ['/configured-vars']))
            base.conf.substitutions['stream'] = '9-stream'
        def read_repos():
            order.append('repositories')
            self.assertEqual(base.conf.substitutions['stream'], '9-stream')
        base.conf.read.side_effect = read_conf
        base.conf.substitutions.update_from_etc.side_effect = load_vars
        base.read_all_repos.side_effect = read_repos
        row = measured_condition(False, base)
        self.assertEqual(order, ['config', 'variables', 'repositories'])
        self.assertEqual(row['substitutions']['before']['stream'], 'MISSING')
        self.assertEqual(row['substitutions']['after']['stream'], 'EXPECTED')
        self.assertTrue(h.valid_substitutions(row['substitutions'], w, success=True))

    def test_already_loaded_value_and_other_substitutions_are_preserved(self):
        conf = configuration()
        conf.substitutions.update(stream='9-stream', unrelated='SECRET')
        value = w.load_substitutions(conf)
        self.assertTrue(all(v == 'EXPECTED' for v in value['before'].values()))
        self.assertEqual(conf.substitutions['unrelated'], 'SECRET')
        self.assertNotIn('SECRET', json.dumps(value))
        self.assertNotIn('unrelated', json.dumps(value))

    def test_missing_stream_is_not_hardcoded_and_stops_before_repository_read(self):
        base, trace = Base(), trace_state()
        base.conf.substitutions.update_from_etc.side_effect = None
        base.fill_sack = Mock()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(w.Stop, '^DNF_SUBSTITUTION_MISMATCH$'):
                w.condition(fake_dnf(base), directory, False, trace)
            self.assertFalse((Path(directory) / 'cachedir').exists())
        self.assertEqual(trace['substitutions']['after']['stream'], 'MISSING')
        self.assertEqual(trace['stage'], 'variable_read')
        base.read_all_repos.assert_not_called()
        base.fill_sack.assert_not_called()

    def test_unexpected_release_arch_and_stream_values_stop_without_disclosure(self):
        for key in w.SUBSTITUTION_EXPECTED:
            for bad in ('SECRET', '', None, True, 9, ['SECRET']):
                conf = configuration()
                conf.substitutions.update(w.SUBSTITUTION_EXPECTED)
                conf.substitutions[key] = bad
                conf.substitutions.update_from_etc.side_effect = None
                trace = trace_state()
                with self.assertRaisesRegex(w.Stop, '^DNF_SUBSTITUTION_MISMATCH$'):
                    w.load_substitutions(conf, trace)
                self.assertEqual(trace['substitutions']['after'][key], 'OTHER')
                self.assertNotIn('SECRET', json.dumps(trace))

    def test_variable_load_failure_retains_started_state(self):
        base, trace = Base(), trace_state()
        base.conf.substitutions.update_from_etc.side_effect = PermissionError('SECRET')
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(PermissionError):
            w.configure(base, directory, False, trace)
        self.assertEqual(trace['substitutions']['state'], 'STARTED')
        self.assertTrue(all(v == 'UNKNOWN' for v in trace['substitutions']['after'].values()))
        self.assertTrue(h.valid_substitutions(trace['substitutions'], w))
        self.assertNotIn('SECRET', json.dumps(trace))
        base.read_all_repos.assert_not_called()

    def test_repository_unexpanded_variables_stop_before_metadata(self):
        for key, value in [('metalink', 'https://example.invalid/?r=$stream'),
                           ('mirrorlist', 'https://example.invalid/${basearch}'),
                           ('baseurl', ['https://example.invalid/%24stream'])]:
            base = Base()
            setattr(base.repos['baseos'], key, value)
            base.fill_sack = Mock()
            with self.assertRaisesRegex(w.Stop, '^REPOSITORY_UNEXPANDED_VARIABLE$'):
                measured_condition(False, base)
            base.fill_sack.assert_not_called()

    def test_unselected_repository_url_is_not_required_to_expand(self):
        base = Base()
        base.repos['extras-common'].metalink = 'https://example.invalid/$unrelated'
        self.assertEqual(measured_condition(False, base)['resolution'], 'MISSING_CANDIDATES')

    def test_initial_not_started_evidence_cannot_authorize_success(self):
        value = w.empty_substitutions()
        self.assertTrue(h.valid_substitutions(value, w))
        self.assertFalse(h.valid_substitutions(value, w, success=True))

    def test_host_rejects_extra_keys_wrong_types_and_inconsistent_states(self):
        good = w.load_substitutions(configuration())
        mutations = [lambda v: v.update(extra='SECRET'),
                     lambda v: v.update(state='SECRET'),
                     lambda v: v.update(state=True),
                     lambda v: v.update(before=[]),
                     lambda v: v['after'].update(stream='SECRET'),
                     lambda v: v['after'].update(stream=True),
                     lambda v: v['after'].update(extra='SECRET'),
                     lambda v: v['after'].pop('stream'),
                     lambda v: v['after'].update(stream='UNKNOWN'),
                     lambda v: v.update(state='NOT_STARTED'),
                     lambda v: v.update(state='STARTED')]
        for mutate in mutations:
            value = copy.deepcopy(good)
            mutate(value)
            self.assertFalse(h.valid_substitutions(value, w))
            payload = failure_report()
            payload['diagnostic']['substitutions'] = value
            result = h.failure_summary(json.dumps(payload), w)
            self.assertEqual(result, {'state': 'INVALID_SCHEMA'})

    def test_host_rejects_success_with_missing_or_unexpected_substitution(self):
        for code in ('MISSING', 'OTHER'):
            value = report()
            value['conditions'][0]['substitutions']['after']['stream'] = code
            with self.assertRaises(h.Stop):
                h.validate(value, w)

    def test_failure_evidence_is_retained_without_becoming_success(self):
        payload = failure_report()
        payload['diagnostic']['substitutions'] = w.load_substitutions(configuration())
        value = h.failure_summary(json.dumps(payload), w)
        self.assertEqual(value['state'], 'VALIDATED_FAILURE_ONLY')
        self.assertEqual(value['diagnostic']['substitutions'], payload['diagnostic']['substitutions'])

    def test_both_conditions_capture_their_own_initial_substitutions(self):
        states = [measured_condition(crb)['substitutions'] for crb in (False, True)]
        for state in states:
            self.assertEqual(state['before']['stream'], 'MISSING')
            self.assertEqual(state['after']['stream'], 'EXPECTED')


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
            baseline, selected, substitutions = w.configure(base, directory, False)
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

    def run_host(self, value=None, rc=0, stderr='', cleanup=True, timeout=False, stdout=None):
        rt = SimpleNamespace(**{k: getattr(runtime, k) for k in ('DOCKER', 'TARGET', 'TARGET_CONFIG', 'TARGET_MANIFEST')})
        rt.command, rt.inspect_image, rt.cleanup = Mock(return_value=''), Mock(return_value={}), Mock(return_value=cleanup)
        inv = SimpleNamespace(now=lambda: '2026-11-15T00:00:00Z', registry_identity=lambda *a: {
            'platform_manifest_digest': runtime.TARGET_MANIFEST, 'config_digest': runtime.TARGET_CONFIG})
        modules = {'runtime_smoke': rt, 'env_probe': inv, 'dependency_container_probe': w}
        proc = SimpleNamespace(returncode=rc, stdout=(json.dumps(report() if value is None else value)
                                                     if stdout is None else stdout), stderr=stderr)
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

    def test_stderr_still_stops_but_valid_failure_diagnostic_survives(self):
        rc, saved, _ = self.run_host(value=failure_report(), rc=3, stderr='SECRET')
        self.assertEqual((rc, saved['status'], saved['reason']),
                         (3, 'INCOMPLETE', 'WORKER_OUTPUT_REJECTED'))
        self.assertEqual(saved['failure_diagnostic']['state'], 'VALIDATED_FAILURE_ONLY')
        self.assertEqual(saved['failure_diagnostic']['diagnostic']['stage'], 'metadata_load')
        self.assertTrue(saved['cleanup_confirmed'])
        self.assertNotIn('measurement', saved)
        self.assertNotIn('SECRET', json.dumps(saved))

    def test_success_report_with_stderr_cannot_be_promoted_to_success(self):
        rc, saved, _ = self.run_host(stderr='SECRET')
        self.assertEqual((rc, saved['reason']), (3, 'WORKER_OUTPUT_REJECTED'))
        self.assertEqual(saved['failure_diagnostic']['state'], 'NOT_A_FAILURE_REPORT')
        self.assertNotIn('measurement', saved)

    def test_malformed_worker_output_with_stderr_does_not_leak_or_pass(self):
        for value in ('SECRET', '{"SECRET":', 'SECRET' * 60000):
            rc, saved, _ = self.run_host(stdout=value, rc=3, stderr='SECRET')
            self.assertEqual((rc, saved['reason']), (3, 'WORKER_OUTPUT_REJECTED'))
            self.assertTrue(saved['cleanup_confirmed'])
            self.assertNotIn('SECRET', json.dumps(saved))
            self.assertNotIn('measurement', saved)

    def test_cleanup_failure_has_priority_and_keeps_safe_diagnostic(self):
        rc, saved, _ = self.run_host(value=failure_report(), rc=3, stderr='SECRET', cleanup=False)
        self.assertEqual((rc, saved['reason']), (3, 'CLEANUP_UNCONFIRMED'))
        self.assertEqual(saved['failure_diagnostic']['state'], 'VALIDATED_FAILURE_ONLY')
        self.assertFalse(saved['cleanup_confirmed'])

    def test_failure_without_stderr_retains_details_without_success(self):
        rc, saved, _ = self.run_host(value=failure_report(), rc=3)
        self.assertEqual((rc, saved['reason']), (3, 'DEPENDENCY_MEASUREMENT_INCOMPLETE'))
        self.assertEqual(saved['failure_diagnostic']['state'], 'VALIDATED_FAILURE_ONLY')
        self.assertFalse(saved['p1_03_complete'])
        self.assertFalse(saved['phase1_complete'])

    def test_config_retains_gates_and_single_job(self):
        config = yaml.safe_load((ROOT / '.circleci/config.yml').read_text())
        self.assertFalse(config['parameters']['run_p1_env_probe']['default'])
        workflow = config['workflows']['p1-environment-measurement']
        self.assertEqual(workflow['jobs'], ['p1-environment'])
        self.assertEqual(workflow['when']['and'], [
            {'not': '<< pipeline.parameters.run_v020_release_matrix >>'},
            {'not': '<< pipeline.parameters.run_v010_release_checks >>'}, '<< pipeline.parameters.run_p1_env_probe >>',
                         {'not': '<< pipeline.parameters.run_p1_build_probe >>'},
                         {'equal': [h.BRANCH, '<< pipeline.git.branch >>']}])
        job = config['jobs']['p1-environment']
        self.assertEqual(job['machine']['image'], 'ubuntu-2204:2023.10.1')
        self.assertEqual(job['resource_class'], 'medium')
        command = job['steps'][1]['run']['command']
        self.assertIn('scripts/p1/ansible_download_probe.py', command)
        self.assertIn('--allow-ci-docker-api', command)
        self.assertIn('--allow-ansible-download', command)
        self.assertNotIn('--allow-rust-install', command)
        self.assertNotIn('--allow-install', command)
        self.assertNotIn('--allow-source-download', command)
        self.assertIn('60s 11m', command)
        self.assertEqual(job['steps'][1]['run']['no_output_timeout'], '12m')


if __name__ == '__main__':
    unittest.main()
