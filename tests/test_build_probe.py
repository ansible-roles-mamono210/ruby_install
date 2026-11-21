"""Offline boundary tests for r39; these are not Ruby build or CI results."""
import copy
import gzip
import hashlib
import io
import itertools
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
import yaml
from unittest.mock import Mock, patch

from test_install_probe import module, host as install_host
from test_rust_install_probe import fixture as dependency_fixture, PLAN, h as rust_host, w as rust_worker
from test_archive_audit import entry, valid_entries as archive_entries, tar_bytes

worker = module('build_container_probe')
host = module('build_probe')
source = module('source_container_probe')
installer = module('install_container_probe')
dependency = rust_host.profile(module('dependency_container_probe'))
dependency_host = module('dependency_probe')


def phase_snapshot(at=0, max_events=0):
    return {'at_seconds': at, 'current_bytes': 100, 'lifetime_peak_bytes': 200,
            'stat_bytes': {'anon': 40, 'file': 60},
            'events': {'source': '/sys/fs/cgroup/memory.events.local',
                       'counters': {'low': 0, 'high': 0, 'max': max_events, 'oom': 0, 'oom_kill': 0}}}


def phase_fixture():
    return [{'name': name, 'sample_count': 2, 'current_unavailable_samples': 0,
             'current_peak_bytes_sampled': 100, 'before': phase_snapshot(i * 2),
             'after': phase_snapshot(i * 2 + 1, 2), 'completed': True,
             'events_delta': {'low': 0, 'high': 0, 'max': 2, 'oom': 0, 'oom_kill': 0}}
            for i, name in enumerate(host.PHASE_NAMES)]


class PhaseMemoryTests(unittest.TestCase):
    def test_scalar_unavailable_or_malformed_is_not_zero(self):
        for value in (None, '', 'max', '-1', '123secret', str(2 ** 63)):
            with self.subTest(value=value), patch.object(worker, 'memory_text', return_value=value):
                self.assertIsNone(worker.memory_scalar('memory.current'))
        with patch.object(worker, 'memory_text', return_value='0\n'):
            self.assertEqual(worker.memory_scalar('memory.current'), 0)

    def test_read_is_bounded_and_errors_do_not_escape(self):
        for error in (FileNotFoundError('PRIVATE'), PermissionError('PRIVATE')):
            with patch.object(worker.Path, 'open', side_effect=error):
                self.assertIsNone(worker.memory_text('memory.current'))
        with patch.object(worker.Path, 'open', return_value=io.StringIO('1' * 8193)):
            self.assertIsNone(worker.memory_text('memory.current'))

    def test_stat_uses_names_not_order_and_drops_unknown_fields(self):
        with patch.object(worker, 'memory_text', return_value='file 6\nsecret PRIVATE\nanon 4\n'):
            self.assertEqual(worker.memory_stat_snapshot(), {'file': 6, 'anon': 4})
        for text in ('anon 4\n', 'anon 4\nfile 6\nanon 5', 'anon -1\nfile 6'):
            with patch.object(worker, 'memory_text', return_value=text):
                self.assertIsNone(worker.memory_stat_snapshot())

    def test_phase_keeps_boundary_events_and_sampled_current_separate(self):
        meter = worker.Meter('/unused')
        samples = [phase_snapshot(0, 10), phase_snapshot(1, 12), phase_snapshot(2, 15)]
        samples[1]['current_bytes'] = 150
        with patch.object(worker, 'memory_snapshot', side_effect=samples):
            meter.begin_phase('dependencies'); meter.sample_memory(); meter.end_phase(True)
        row = meter.data['memory_phases'][0]
        self.assertEqual(row['events_delta']['max'], 5)
        self.assertEqual(row['current_peak_bytes_sampled'], 150)
        self.assertEqual(row['after']['lifetime_peak_bytes'], 200)
        self.assertEqual(row['sample_count'], 3)
        self.assertIsNone(meter.active_phase)

    def test_missing_events_source_change_or_counter_reset_has_no_delta(self):
        before = phase_snapshot()['events']
        for after in (None, dict(before, source='/sys/fs/cgroup/memory.events'),
                      dict(before, counters=dict(before['counters'], max=-1))):
            self.assertIsNone(worker.event_delta(before, after))

    def test_run_failure_retains_phase_end_and_original_error(self):
        meter = worker.Meter('/unused')
        with patch.object(worker, 'memory_snapshot', side_effect=[phase_snapshot(), phase_snapshot(1, 3)]), \
                patch.object(worker, 'run_command', side_effect=worker.Stop('BUILD_TIME_LIMIT')):
            with self.assertRaisesRegex(worker.Stop, 'BUILD_TIME_LIMIT'):
                worker.run('configure', [], '/', '/', {'runs': []}, meter, 1, 1)
        row = meter.data['memory_phases'][0]
        self.assertFalse(row['completed']); self.assertEqual(row['events_delta']['max'], 3)

    def test_missing_current_counts_as_unavailable_not_zero(self):
        meter = worker.Meter('/unused'); snapshot = phase_snapshot()
        snapshot['current_bytes'] = None
        with patch.object(worker, 'memory_snapshot', return_value=snapshot):
            meter.begin_phase('dependencies'); meter.end_phase(False)
        row = meter.data['memory_phases'][0]
        self.assertEqual(row['current_unavailable_samples'], 2)
        self.assertIsNone(row['current_peak_bytes_sampled'])
        self.assertIsNotNone(host.checked_memory_phases([row]))
        self.assertIsNone(host.checked_memory_phases([row], complete=True))

    def test_host_rejects_missing_reordered_forged_and_unbounded_records(self):
        self.assertIsNotNone(host.checked_memory_phases(phase_fixture(), complete=True))
        for mode in ('missing', 'reorder', 'delta', 'bool', 'secret', 'time', 'incomplete'):
            rows = phase_fixture()
            if mode == 'missing': rows.pop()
            if mode == 'reorder': rows[0], rows[1] = rows[1], rows[0]
            if mode == 'delta': rows[0]['events_delta']['max'] = 999
            if mode == 'bool': rows[0]['before']['current_bytes'] = True
            if mode == 'secret': rows[0]['before']['secret'] = 'PRIVATE'
            if mode == 'time': rows[0]['after']['at_seconds'] = float('nan')
            if mode == 'incomplete': rows[-1]['completed'] = False
            with self.subTest(mode=mode):
                self.assertIsNone(host.checked_memory_phases(rows, complete=True))

    def test_partial_phases_survive_failure_but_unknown_fields_do_not(self):
        phases = phase_fixture()[:2]; phases[-1]['completed'] = False
        row = {'resources': {'memory_phases': phases}}
        self.assertEqual(host.partial_measurements(row)['resources']['memory_phases'], phases)
        phases[0]['secret'] = 'PRIVATE'
        self.assertNotIn('PRIVATE', json.dumps(host.partial_measurements(row)))

    def test_diagnostic_requires_explicit_flag_before_output(self):
        with patch.object(host.os, 'open') as output, patch('builtins.print'), \
                patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': host.BRANCH}), \
                patch.object(host.platform, 'system', return_value='Linux'), \
                patch.object(host.platform, 'machine', return_value='x86_64'):
            result = host.main(['--output', '/unused', '--allow-pull', '--allow-install',
                    '--allow-rust-install', '--allow-ci430-replacements',
                    '--allow-ruby-3412-rust-build', '--ephemeral-ci'])
        self.assertEqual(result, 3); output.assert_not_called()

    def test_timeout_envelope_and_resources(self):
        config = yaml.safe_load((host.ROOT.parents[1] / '.circleci/config.yml').read_text())
        run = config['jobs']['p1-ruby-build']['steps'][1]['run']
        self.assertEqual(run['no_output_timeout'], '16m')
        self.assertIn('--kill-after=60s 15m', run['command'])
        self.assertIn('--allow-memory-diagnostic', run['command'])
        argv = host.arguments(SimpleNamespace(DOCKER=['docker'], TARGET_CONFIG='fixed'), 'name', 'id')
        self.assertEqual(argv[argv.index('--memory') + 1], '2g')
        self.assertNotIn('--privileged', argv)


def valid_entries():
    return copy.deepcopy(archive_entries())


def runtime_fixture():
    return {'version': '3.4.12', 'ruby': '/opt/ruby/bin/ruby', 'prefix': '/opt/ruby',
            'shared': 'yes', 'yjit_build': 'no', 'rjit_build': 'no',
            'jit': {'YJIT': False, 'RJIT': 'absent'},
            'shared_libraries': ['/opt/ruby/lib/libruby.so.3.4.12'],
            'ri_system': '/opt/ruby/share/ri/3.4.0/system',
            'extensions': dict(openssl='test', psych='test', zlib='test', fiddle='test')}


class ExtractionTests(unittest.TestCase):
    def attempt(self, entries=None, mutate_audit=None, changed=False):
        entries = valid_entries() if entries is None else entries
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'source.gz'
            archive.write_bytes(gzip.compress(tar_bytes(entries)))
            audit = source.audit_archive(archive, worker.VERSION, time.monotonic() + 30)
            if mutate_audit:
                mutate_audit(audit)
            destination = Path(directory) / 'out'
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            if changed:
                archive.write_bytes(archive.read_bytes() + b'extra')
            with patch.object(tarfile.TarFile, 'extractall', side_effect=AssertionError('extractall')):
                result = worker.extract(source, archive, destination, audit, digest)
            return [(str(p.relative_to(result)), p.is_symlink()) for p in result.rglob('*')]

    def test_valid_files(self):
        self.assertEqual(len(self.attempt()), 3)

    def test_contained_hardlink_and_symlink(self):
        entries = valid_entries() + [entry('ruby-3.4.12/hard', kind=tarfile.LNKTYPE,
                                         target='ruby-3.4.12/configure'),
                                     entry('ruby-3.4.12/soft', kind=tarfile.SYMTYPE, target='configure')]
        self.assertIn(('soft', True), self.attempt(entries))

    def test_checksum_change_stops_before_extraction(self):
        with self.assertRaisesRegex(worker.Stop, 'EXTRACT_CHECKSUM'):
            self.attempt(changed=True)

    def test_parser_count_disagreement_stops(self):
        with self.assertRaisesRegex(worker.Stop, 'EXTRACT_AUDIT_MISMATCH'):
            self.attempt(mutate_audit=lambda a: a.update(members=999))

    def test_escape_and_link_parent_rejected(self):
        for entries in (valid_entries() + [entry('ruby-3.4.12/../outside')],
                        valid_entries() + [entry('ruby-3.4.12/evil', kind=tarfile.SYMTYPE, target='/tmp'),
                                           entry('ruby-3.4.12/evil/file')]):
            with self.subTest(entries=entries[-1][0].name), self.assertRaises(source.Stop):
                self.attempt(entries)

    def test_executable_mode_and_release_timestamp_preserved(self):
        entries = valid_entries()
        entries[1][0].mode, entries[1][0].mtime = 0o755, 1700000000
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'a.gz'
            archive.write_bytes(gzip.compress(tar_bytes(entries)))
            audit = source.audit_archive(archive, worker.VERSION, time.monotonic() + 30)
            extracted = worker.extract(source, archive, Path(directory) / 'out', audit,
                                       hashlib.sha256(archive.read_bytes()).hexdigest())
            info = (extracted / 'configure').stat()
            self.assertTrue(info.st_mode & 0o111)
            self.assertEqual(info.st_mtime, 1700000000)


class MountTests(unittest.TestCase):
    ROOT = '10 0 8:1 / / rw,relatime - ext4 /dev/root rw\n'

    def test_inherited_mount(self):
        self.assertEqual(worker.mount_for('/tmp', self.ROOT)['mount_point'], '/')

    def test_longest_mount_and_not_sibling_prefix(self):
        text = self.ROOT + '11 10 0:1 / /tmp rw,noexec - tmpfs tmpfs rw\n'
        self.assertIn('noexec', worker.mount_for('/tmp/build', text)['options'])
        self.assertEqual(worker.mount_for('/tmp-other', text)['mount_point'], '/')

    def test_malformed_mount_not_ignored(self):
        with self.assertRaisesRegex(worker.Stop, 'MOUNT_FORMAT'):
            worker.mount_for('/tmp', 'broken')

    def test_preflight_failure_precedes_dependency_transaction(self):
        execute = Mock()
        with patch.object(worker, 'preflight', side_effect=worker.Stop('WORKSPACE_NOEXEC')), \
                patch.object(worker, 'evaluate', execute), patch('builtins.print') as printed:
            self.assertEqual(worker.main(source, installer, dependency, PLAN, rust_worker), 3)
        execute.assert_not_called()
        self.assertEqual(json.loads(printed.call_args.args[0])['reason'], 'WORKSPACE_NOEXEC')


class SettingsTests(unittest.TestCase):
    def make_settings(self, directory, yjit=0, docs='rdoc nodoc'):
        root = Path(directory)
        (root / 'Makefile').write_text('prefix = /opt/ruby\nENABLE_SHARED = yes\n'
            'YJIT_SUPPORT=no\nRJIT_SUPPORT = no\nDOCTARGETS = ' + docs +
            '\nINSTALLDOC = all\nEXTOUT = .ext\n')
        header = root / '.ext/include/x86_64-linux/ruby/config.h'
        header.parent.mkdir(parents=True)
        header.write_text('#define USE_YJIT ' + str(yjit) + '\n#define USE_RJIT 0\n')
        log = root / 'configure.log'
        log.write_text('   * YJIT support:        no\n   * RJIT support:        no\n'
                       '   * install doc:         rdoc\n')
        return log

    def test_summary_makefile_header_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            result = worker.build_settings(Path(directory), self.make_settings(directory))
        self.assertEqual(result['USE_RJIT'], 0)

    def test_enabled_macro_fails_even_with_disabled_summary(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(worker.Stop, 'JIT_BUILD_ENABLED'):
            worker.build_settings(Path(directory), self.make_settings(directory, yjit=1))

    def test_docs_disabled_fails(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(worker.Stop, 'BUILD_SETTING_MISMATCH'):
            worker.build_settings(Path(directory), self.make_settings(directory, docs='nodoc nodoc'))

    def test_runtime_good(self):
        worker.validate_runtime(runtime_fixture())

    def test_runtime_wrong_ruby_or_external_shared_library(self):
        for key, value in (('version', '3.2.3'), ('prefix', '/usr/local'), ('ruby', '/usr/bin/ruby'),
                           ('shared_libraries', ['/usr/lib/libruby.so']), ('rjit_build', 'yes'),
                           ('jit', {'YJIT': True, 'RJIT': False})):
            row = runtime_fixture()
            row[key] = value
            with self.subTest(key=key), self.assertRaises(worker.Stop):
                worker.validate_runtime(row)


class ProcessTests(unittest.TestCase):
    def test_clean_environment_excludes_parent_overrides(self):
        with patch.dict(os.environ, {'RUBYOPT': '--yjit', 'LD_LIBRARY_PATH': '/evil', 'GEM_HOME': '/evil'}):
            env = worker.clean_env('/tmp/example')
        for key in ('RUBYOPT', 'LD_LIBRARY_PATH', 'GEM_HOME', 'MAKEFLAGS'):
            self.assertNotIn(key, env)

    def test_command_logs_and_exit_are_retained_on_failure(self):
        report = {'runs': []}
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(worker.Stop, 'COMMAND_FAILED'):
                worker.run('failure', [sys.executable, '-c', 'print("diagnostic"); raise SystemExit(4)'],
                           directory, directory, report, Mock(), 3, time.monotonic() + 5)
        self.assertEqual(report['runs'][0]['returncode'], 4)
        self.assertIn('diagnostic', report['runs'][0]['tail'])

    def test_timeout_terminates_child_and_records_result(self):
        report = {'runs': []}
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(worker.Stop, 'BUILD_TIME_LIMIT'):
                worker.run('timeout', [sys.executable, '-c', 'import time;time.sleep(30)'],
                           directory, directory, report, Mock(), 0.1, time.monotonic() + 3)
        self.assertEqual(report['runs'][0]['returncode'], -9)


class DocumentationRegressionTests(unittest.TestCase):
    def test_formatter_is_supported_by_actual_ci420_help(self):
        text = (Path(__file__).parent / 'fixtures/ci420_ri_help.txt').read_text()
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(),
                         '0d6c293c7f63e9f6ecc547ab5ee462ea90091642c257f4ab3c33d39690bb39e8')
        formats = re.search(r'Valid formatters are:\s+([^\n]+)\.', text)[1].split(', ')
        argv = worker.documentation_arguments('/opt/ruby/share/ri/3.4.0/system')
        selected = next(arg.split('=', 1)[1] for arg in argv if arg.startswith('--format='))
        self.assertIn(selected, formats)
        self.assertNotIn('plain', formats)  # The failure seen in the real CI run.

    def test_documentation_lookup_keeps_only_the_requested_store(self):
        docs = '/opt/ruby/share/ri/3.4.0/system'
        argv = worker.documentation_arguments(docs)
        self.assertEqual(argv[0], '/opt/ruby/bin/ri')
        self.assertEqual([arg for arg in argv if arg.startswith('--doc-dir=')], ['--doc-dir=' + docs])
        self.assertIn('--no-standard-docs', argv)
        self.assertIn('--no-pager', argv)
        self.assertEqual(argv[-1], 'String')
        for extra_store in ('--system', '--site', '--home', '--gems'):
            self.assertNotIn(extra_store, argv)


class Ruby3412RustPresentTests(unittest.TestCase):
    def validate(self, row):
        host.validate(row, PLAN, worker, installer, install_host, dependency_host, dependency)

    def test_jit_disabled_with_documentation_and_default_prefix(self):
        self.assertEqual(worker.VERSION, '3.4.12')
        self.assertEqual(worker.PREFIX, '/opt/ruby')
        for option in ('--prefix=/opt/ruby', '--disable-yjit', '--disable-rjit',
                       '--enable-install-doc', '--enable-install-rdoc', '--disable-install-capi'):
            self.assertIn(option, worker.CONFIGURE)
        self.assertNotIn('--disable-install-doc', worker.CONFIGURE)

    def test_install_target_and_output_location_must_match(self):
        for old, new in (('INSTALLDOC = all', 'INSTALLDOC = nodoc'),
                         ('EXTOUT = .ext', 'EXTOUT = /elsewhere')):
            with self.subTest(new=new), tempfile.TemporaryDirectory() as directory:
                log = SettingsTests().make_settings(directory)
                path = Path(directory) / 'Makefile'
                path.write_text(path.read_text().replace(old, new))
                with self.assertRaisesRegex(worker.Stop, 'BUILD_SETTING_MISMATCH'):
                    worker.build_settings(Path(directory), log)

    def test_configure_summary_must_enable_documentation(self):
        with tempfile.TemporaryDirectory() as directory:
            log = SettingsTests().make_settings(directory)
            log.write_text(log.read_text().replace('install doc:         rdoc', 'install doc:         no'))
            with self.assertRaisesRegex(worker.Stop, 'DOCUMENTATION_SUMMARY_MISMATCH'):
                worker.build_settings(Path(directory), log)

    def test_standard_documentation_lookup_is_required(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(worker, 'PREFIX', directory):
            docs = Path(directory) / 'share/ri/3.4.0/system'
            (docs / 'String').mkdir(parents=True)
            (docs / 'String/cdesc-String.ri').write_bytes(b'fixture')
            log = Path(directory) / 'ri.log';log.write_text('String' * 100)
            with patch.object(worker, 'run', return_value=log) as run:
                result = worker.documentation_on({'ri_system': str(docs)}, directory, {}, Mock(), 100)
            self.assertIs(result['standard_String_verified'], True)
            self.assertEqual(run.call_args.args[0], 'ri-String')

    def test_missing_or_external_documentation_stops_before_lookup(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(worker, 'PREFIX', directory):
            for docs in (directory + '/share/ri/3.4.0/system', '/elsewhere'):
                with self.subTest(path=docs), patch.object(worker, 'run') as run, \
                        self.assertRaisesRegex(worker.Stop, 'STANDARD_DOCUMENTATION_MISSING'):
                    worker.documentation_on({'ri_system': docs}, directory, {}, Mock(), 100)
                run.assert_not_called()

    def test_wrong_ri_output_rejected(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(worker, 'PREFIX', directory):
            docs = Path(directory) / 'share/ri/3.4.0/system'
            (docs / 'String').mkdir(parents=True);(docs / 'String/cdesc-String.ri').touch()
            log = Path(directory) / 'ri.log';log.write_text('x' * 200)
            with patch.object(worker, 'run', return_value=log), \
                    self.assertRaisesRegex(worker.Stop, 'STANDARD_DOCUMENTATION_FAILED'):
                worker.documentation_on({'ri_system': str(docs)}, directory, {}, Mock(), 100)

    def test_shebang_uses_exact_managed_ruby(self):
        worker.validate_shebang('#!' + worker.PREFIX + '/bin/ruby\n')
        for wrong in ('/opt/ruby-other/bin/ruby', '/usr/bin/env ruby', worker.PREFIX + '/bin/ruby-other'):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(worker.Stop, 'COMMAND_EXTERNAL_RUBY'):
                worker.validate_shebang('#!' + wrong + '\n')

    def test_host_requires_rust_present_docs_on_condition(self):
        base = HostTests().success_fixture()
        for change in ({'ruby': '4.0.9'}, {'rust': False}, {'documentation': False}, {'prefix': '/other'}):
            with self.subTest(change=change), self.assertRaises(host.Stop):
                self.validate(dict(base, condition=dict(base['condition'], **change)))
        with self.assertRaises(host.Stop):
            self.validate(dict(base, rust_present_after_dependencies=False))

    def test_host_requires_all_documentation_evidence(self):
        for key, value in (('enabled', False), ('standard_String_verified', False),
                ('other_stores_disabled', False), ('system_dir', '/elsewhere'),
                ('enabled', 1), ('standard_String_verified', 1), ('other_stores_disabled', 1)):
            row = HostTests().success_fixture();row['documentation'][key] = value
            with self.subTest(key=key,value=value), self.assertRaisesRegex(host.Stop, 'BUILD_DOCUMENTATION_SCHEMA'):
                self.validate(row)

    def test_host_rejects_missing_or_failed_ri_lookup(self):
        for mode in ('missing', 'failed'):
            row = HostTests().success_fixture()
            if mode == 'missing':row['runs'].pop()
            else:row['runs'][-1]['returncode'] = 1
            with self.subTest(mode=mode), self.assertRaises(host.Stop):self.validate(row)

    def test_source_selects_exact_ruby3412_tuple(self):
        self.assertEqual(worker.source_spec(source), source.SOURCES[0])

    def test_source_drift_stops_before_network(self):
        fixed = source.SOURCES[0]
        for items, hostname in ((source.SOURCES[1:], source.HOST), ((fixed, fixed), source.HOST),
                (((fixed[0], '/different', fixed[2]),), source.HOST),
                (((fixed[0], fixed[1], '0' * 64),), source.HOST), ((fixed,), 'elsewhere.invalid')):
            with self.subTest(items=items), patch.object(worker.http.client, 'HTTPSConnection') as network, \
                    self.assertRaisesRegex(worker.Stop, 'SOURCE_CHANGED'):
                worker.download(SimpleNamespace(SOURCES=items, HOST=hostname), '/unused', {})
            network.assert_not_called()

    def test_rjit_header_summary_and_runtime_must_be_disabled(self):
        for location in ('header', 'summary'):
            with self.subTest(location=location), tempfile.TemporaryDirectory() as directory:
                log = SettingsTests().make_settings(directory)
                target = log if location == 'summary' else next(Path(directory).glob('.ext/include/*/ruby/config.h'))
                target.write_text(target.read_text().replace('USE_RJIT 0', 'USE_RJIT 1') if location == 'header'
                                  else target.read_text().replace('RJIT support:        no', 'RJIT support:        yes'))
                with self.assertRaises(worker.Stop):worker.build_settings(Path(directory), log)
        row = runtime_fixture();row['jit'] = {'YJIT': False, 'ZJIT': False}
        with self.assertRaisesRegex(worker.Stop, 'RUNTIME_JIT'):worker.validate_runtime(row)

    def test_ci_requires_new_build_and_rust_flags(self):
        config = yaml.safe_load((host.ROOT.parents[1] / '.circleci/config.yml').read_text())
        command = config['jobs']['p1-ruby-build']['steps'][1]['run']['command']
        for flag in ('--allow-ruby-3412-rust-build', '--allow-rust-install', '--allow-ci430-replacements'):
            self.assertIn(flag, command)
        self.assertNotIn('--allow-ci416-replacements', command)

    def test_each_required_flag_is_checked_before_any_output_or_docker(self):
        flags = ['--allow-pull', '--allow-install',
                 '--allow-rust-install', '--allow-ci430-replacements', '--allow-ruby-3412-rust-build',
                 '--allow-memory-diagnostic', '--ephemeral-ci']
        for missing in flags:
            with self.subTest(missing=missing), patch.object(host.os, 'open') as output, \
                    patch.object(host.subprocess, 'run') as run, patch('builtins.print'), \
                    patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': host.BRANCH}), \
                    patch.object(host.platform, 'system', return_value='Linux'), \
                    patch.object(host.platform, 'machine', return_value='x86_64'):
                self.assertEqual(host.main(['--output','/unused']+[f for f in flags if f!=missing]), 3)
            output.assert_not_called();run.assert_not_called()
        with patch.object(host.os, 'open', side_effect=OSError) as output, \
                patch.object(host.subprocess, 'run') as run, patch('builtins.print') as message, \
                patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': host.BRANCH}), \
                patch.object(host.platform, 'system', return_value='Linux'), \
                patch.object(host.platform, 'machine', return_value='x86_64'):
            self.assertEqual(host.main(['--output', '/unused'] + flags), 3)
        output.assert_called_once()
        run.assert_not_called()
        message.assert_called_once_with('STOP: OUTPUT_UNAVAILABLE_OR_EXISTS')

    def test_old_flags_cannot_authorize_this_condition(self):
        for old in ('--allow-ruby-409-docs-off-build', '--allow-ruby-409-docs-on-build',
                    '--allow-ruby-3412-docs-off-build', '--allow-ruby-3412-build',
                    '--allow-ruby-409-rust-build', '--allow-ci416-replacements'):
            with self.subTest(flag=old), patch.object(host.os, 'open') as output, \
                    patch.object(host.subprocess, 'run') as run, patch('sys.stderr', io.StringIO()):
                with self.assertRaises(SystemExit):host.main(['--output', '/unused', old])
            output.assert_not_called();run.assert_not_called()

    def test_dependency_rust_failure_stops_before_ruby_download(self):
        fake_dnf = SimpleNamespace(__version__='4.14.0', transaction=object(), callback=object())
        fake_rpm = SimpleNamespace(__version__='4.16.1.3')
        for reason in ('RUST_SMOKE_FAILED', 'TRANSACTION_PLAN_CHANGED'):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as directory, \
                    patch.dict(sys.modules, {'dnf':fake_dnf,'dnf.transaction':fake_dnf.transaction,
                        'dnf.callback':fake_dnf.callback,'rpm':fake_rpm}), \
                    patch.object(worker, 'public_state', return_value={}), patch.object(worker.signal, 'alarm'), \
                    patch.object(rust_worker, 'execute', side_effect=rust_worker.Stop(reason)), \
                    patch.object(worker, 'download') as download, self.assertRaises(rust_worker.Stop):
                worker.evaluate(source, installer, dependency, PLAN, {}, directory, Mock(),
                                time.monotonic()+100, rust_worker)
            download.assert_not_called()

    def test_rust_evidence_and_real_path_required_before_download(self):
        fake_dnf=SimpleNamespace(__version__='4.14.0', transaction=object(), callback=object())
        fake_rpm=SimpleNamespace(__version__='4.16.1.3')
        for missing, path in (('rust_installed','/usr/bin/rustc'),('rust_compiler_checked','/usr/bin/rustc'),
                              (None,'/elsewhere/rustc'),(None,None)):
            def install(*args):
                args[-1].update(dependency_fixture())
                if missing:args[-1][missing]=False
            with self.subTest(missing=missing,path=path), tempfile.TemporaryDirectory() as directory, \
                    patch.dict(sys.modules, {'dnf':fake_dnf,'dnf.transaction':fake_dnf.transaction,
                         'dnf.callback':fake_dnf.callback,'rpm':fake_rpm}), \
                    patch.object(worker, 'public_state', return_value={}), patch.object(worker.signal, 'alarm'), \
                    patch.object(rust_worker, 'execute', side_effect=install), \
                    patch.object(worker.shutil, 'which', return_value=path), patch.object(worker, 'download') as download, \
                    self.assertRaisesRegex(worker.Stop, 'RUST_COMPILER_UNCONFIRMED'):
                worker.evaluate(source, installer, dependency, PLAN, {}, directory, Mock(),
                                time.monotonic()+100, rust_worker)
            download.assert_not_called()

    def test_host_rejects_ci416_or_failed_rust_proof(self):
        for key, value in (('plan_reference','CI416'),('rust_installed',False),
                ('rust_compiler_checked',False),('all_signatures_verified',False),('rust_smoke',[])):
            row=HostTests().success_fixture();row['dependencies'][key]=value
            with self.subTest(key=key), self.assertRaises(host.Stop):self.validate(row)

    def test_non_boolean_condition_flags_cannot_pass(self):
        for change in ({'rust': 1}, {'documentation': 1}, {'make_jobs': True}):
            base=HostTests().success_fixture()
            with self.subTest(change=change), self.assertRaises(host.Stop):
                self.validate(dict(base,condition=dict(base['condition'],**change)))

    def test_existing_prefix_stops_before_workspace_or_dependencies(self):
        with patch.dict(worker.os.environ, {'RUBY_P1_BUILD_PROBE':'r39'}, clear=True), \
                patch.object(worker.os,'getuid',return_value=0), \
                patch.object(worker.platform,'system',return_value='Linux'), \
                patch.object(worker.platform,'machine',return_value='x86_64'), \
                patch.object(worker.platform,'python_version',return_value='3.9.19'), \
                patch.object(worker.Path,'is_file',return_value=True), \
                patch.object(worker.Path,'read_text',return_value='ID=centos\nVERSION_ID=9\n'), \
                patch.object(worker.os.path,'lexists',return_value=True), \
                patch.object(worker.shutil,'disk_usage') as disk, \
                self.assertRaisesRegex(worker.Stop,'PREFIX_EXISTS'):
            worker.preflight()
        disk.assert_not_called()

    def test_diagnostics_preserve_all_fifteen_runs(self):
        row=HostTests().success_fixture()
        self.assertEqual(len(row['runs']),15)
        self.assertEqual(host.diagnostics(row)['runs'][-1]['name'],'ri-String')


class MemoryEventTests(unittest.TestCase):
    TEXT = 'low 0\nhigh 0\nmax 17\noom 2\noom_kill 1\noom_group_kill 0\n'

    def record(self):
        return {'source': '/sys/fs/cgroup/memory.events.local',
                'counters': {'low': 0, 'high': 0, 'max': 17, 'oom': 2,
                             'oom_kill': 1, 'oom_group_kill': 0}}

    def test_local_counters_preferred_and_nonzero_values_preserved(self):
        with patch.object(worker.Path, 'open', return_value=io.StringIO(self.TEXT)) as opened:
            self.assertEqual(worker.memory_events_snapshot(), self.record())
        opened.assert_called_once_with('r', encoding='ascii')

    def test_hierarchical_fallback_is_explicit(self):
        with patch.object(worker.Path, 'open', side_effect=[FileNotFoundError(), io.StringIO(self.TEXT)]) as opened:
            row = worker.memory_events_snapshot()
        self.assertEqual(opened.call_count, 2)
        self.assertEqual(row, dict(self.record(), source='/sys/fs/cgroup/memory.events'))

    def test_missing_unreadable_and_invalid_unicode_are_not_zero(self):
        for failure in (FileNotFoundError(), PermissionError('PRIVATE'), UnicodeError('PRIVATE')):
            with self.subTest(failure=type(failure).__name__), \
                    patch.object(worker.Path, 'open', side_effect=failure):
                self.assertIsNone(worker.memory_events_snapshot())

    def test_unknown_fields_are_excluded_and_optional_counter_may_be_missing(self):
        text = self.TEXT.replace('oom_group_kill 0\n', '') + 'future 9\nsecret PRIVATE\n'
        with patch.object(worker.Path, 'open', return_value=io.StringIO(text)):
            value = worker.memory_events_snapshot()
        expected = self.record();del expected['counters']['oom_group_kill']
        self.assertEqual(value, expected)
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_malformed_duplicate_missing_and_oversized_inputs_are_unavailable(self):
        texts = [self.TEXT + 'max 99\n', self.TEXT.replace('max 17\n', ''),
                 self.TEXT + 'x' * 8193]
        texts += [self.TEXT.replace('max 17', 'max ' + value)
                  for value in ('-1', '1.5', 'true', '1 2', str(2 ** 63), '1' * 20)]
        for text in texts:
            with self.subTest(text=text[:100]), patch.object(worker.Path, 'open', return_value=io.StringIO(text)):
                self.assertIsNone(worker.memory_events_snapshot())

    def test_snapshot_survives_later_disk_sampling_failure(self):
        with patch.object(worker.shutil, 'disk_usage', return_value=SimpleNamespace(free=10 ** 10)):
            meter = worker.Meter('/unused')
        with patch.object(worker, 'memory_events_snapshot', return_value=self.record()), \
                patch.object(worker, 'size_tree', side_effect=OSError('PRIVATE')), self.assertRaises(OSError):
            meter.sample()
        self.assertEqual(meter.data['memory_events'], self.record())

    def test_failure_diagnostics_keep_observations_without_declaring_capacity_safe(self):
        row = FailureMeasurementTests().observation()
        row['resources']['memory_events'] = self.record()
        result = host.diagnostics(row)['partial_measurements']
        self.assertEqual(result['resources']['memory_events'], self.record())
        self.assertIs(result['complete'], False)
        row['resources']['memory_events'] = None
        self.assertIsNone(host.diagnostics(row)['partial_measurements']['resources']['memory_events'])

    def test_host_rejects_invalid_events_and_filters_them_in_failure_output(self):
        invalid = [dict(self.record(), source='/private/SECRET'), dict(self.record(), secret='SECRET'),
                   dict(self.record(), counters={'oom': 0}), [], 'SECRET']
        for value in (True, -1, '1', 1.25, 2 ** 63):
            row = self.record();row['counters']['oom'] = value;invalid.append(row)
        for events in invalid:
            row = HostTests().success_fixture();row['resources']['memory_events'] = events
            with self.subTest(events=events), self.assertRaisesRegex(host.Stop, 'BUILD_MEMORY_EVENTS_SCHEMA'):
                host.validate(row, PLAN, worker, installer, install_host, dependency_host, dependency)
            self.assertNotIn('memory_events', host.partial_measurements(row)['resources'])

    def test_host_preserves_null_or_measured_events_but_requires_the_field(self):
        for events in (None, self.record()):
            row = HostTests().success_fixture();row['resources']['memory_events'] = events
            host.validate(row, PLAN, worker, installer, install_host, dependency_host, dependency)
        del row['resources']['memory_events']
        with self.assertRaisesRegex(host.Stop, 'BUILD_MEMORY_EVENTS_SCHEMA'):
            host.validate(row, PLAN, worker, installer, install_host, dependency_host, dependency)


class FailureMeasurementTests(unittest.TestCase):
    def observation(self):
        return {'schema': worker.SCHEMA, 'status': 'INCOMPLETE', 'stage': 'documentation',
                'reason': 'COMMAND_FAILED', 'runs': [], 'elapsed_seconds': 410.5,
                'resources': {'sample_count': 80, 'sample_interval_seconds': 5,
                    'workspace_peak_allocated_bytes_sampled': 800000000,
                    'prefix_peak_allocated_bytes_sampled': 200000000,
                    'combined_peak_allocated_bytes_sampled': 1000000000,
                    'minimum_free_bytes_sampled': 9000000000,
                    'memory_peak_bytes': 1000000000, 'memory_peak_source': '/sys/fs/cgroup/memory.peak'},
                'prefix_size': {'apparent_bytes': 180000000, 'allocated_bytes': 200000000}}

    def test_partial_values_survive_diagnostics_without_becoming_pass(self):
        row = self.observation()
        result = host.diagnostics(row)
        part = result['partial_measurements']
        self.assertEqual(part['resources'], row['resources'])
        self.assertEqual(part['prefix_size'], row['prefix_size'])
        self.assertEqual(part['elapsed_seconds'], 410.5)
        self.assertIs(part['complete'], False)
        self.assertEqual(result['reason'], 'COMMAND_FAILED')
        with self.assertRaises(host.Stop):
            host.validate(row, PLAN, worker, installer, install_host, dependency_host, dependency)

    def test_unavailable_memory_and_missing_fields_are_not_zero(self):
        row = self.observation()
        row['resources'] = {'memory_peak_bytes': None, 'memory_peak_source': 'unavailable'}
        del row['prefix_size']
        result = host.diagnostics(row)['partial_measurements']
        self.assertIsNone(result['resources']['memory_peak_bytes'])
        self.assertNotIn('sample_count', result['resources'])
        self.assertNotIn('prefix_size', result)

    def test_unknown_keys_paths_and_pass_flags_are_not_retained(self):
        row = self.observation()
        row['resources'].update(secret='PRIVATE', memory_peak_source='/private/secret', phase1_complete=True)
        row['prefix_size'].update(path='/private/secret', token='PRIVATE')
        row.update(phase1_complete=True, measurement_snapshot_error='PRIVATE')
        text = json.dumps(host.diagnostics(row)['partial_measurements'])
        for forbidden in ('PRIVATE', '/private', 'phase1_complete', 'measurement_snapshot_error'):
            self.assertNotIn(forbidden, text)

    def test_invalid_measurements_are_omitted(self):
        for invalid in (True, -1, '123', 1.25, 2 ** 63, float('nan'), float('inf'), [], {}):
            row = self.observation()
            row['resources']['memory_peak_bytes'] = invalid
            row['prefix_size']['allocated_bytes'] = invalid
            with self.subTest(value=repr(invalid)):
                part = host.diagnostics(row)['partial_measurements']
                self.assertNotIn('memory_peak_bytes', part['resources'])
                self.assertNotIn('allocated_bytes', part['prefix_size'])
        for invalid in (True, -1, '123', 2521, float('nan'), float('inf')):
            row = self.observation()
            row['elapsed_seconds'] = invalid
            self.assertNotIn('elapsed_seconds', host.diagnostics(row)['partial_measurements'])

    def test_worker_failure_preserves_final_snapshot(self):
        row = self.observation()
        meter = Mock(data=row['resources'])
        def fail(*args):
            args[4]['stage'] = 'documentation'
            raise worker.Stop('COMMAND_FAILED')
        with patch.object(worker, 'preflight', return_value={}), \
                patch.object(worker.tempfile, 'mkdtemp', return_value='/unused'), \
                patch.object(worker.os, 'umask'), patch.object(worker, 'Meter', return_value=meter), \
                patch.object(worker, 'evaluate', side_effect=fail), \
                patch.object(worker, 'size_tree', return_value=row['prefix_size']), patch('builtins.print') as printed:
            self.assertEqual(worker.main(source, installer, dependency, PLAN, rust_worker), 3)
        saved = json.loads(printed.call_args.args[0])
        self.assertEqual(saved['prefix_size'], row['prefix_size'])
        self.assertEqual(saved['resources'], row['resources'])
        self.assertEqual(saved['reason'], 'COMMAND_FAILED')
        self.assertEqual(saved['status'], 'INCOMPLETE')
        meter.sample.assert_called_once()

    def test_snapshot_error_does_not_replace_original_failure_or_samples(self):
        meter = Mock(data={'sample_count': 12, 'memory_peak_bytes': None})
        meter.sample.side_effect = OSError('PRIVATE')
        with patch.object(worker, 'preflight', return_value={}), \
                patch.object(worker.tempfile, 'mkdtemp', return_value='/unused'), \
                patch.object(worker.os, 'umask'), patch.object(worker, 'Meter', return_value=meter), \
                patch.object(worker, 'evaluate', side_effect=worker.Stop('COMMAND_FAILED')), \
                patch('builtins.print') as printed:
            self.assertEqual(worker.main(source, installer, dependency, PLAN, rust_worker), 3)
        row = json.loads(printed.call_args.args[0])
        self.assertEqual(row['reason'], 'COMMAND_FAILED')
        self.assertEqual(row['resources']['sample_count'], 12)
        part = host.diagnostics(row)['partial_measurements']
        self.assertEqual(part['measurement_snapshot_error'], 'FINAL_RESOURCE_SNAPSHOT_FAILED')
        self.assertNotIn('PRIVATE', printed.call_args.args[0])

    def test_host_persists_partial_result_and_confirms_cleanup_on_worker_failure(self):
        value = self.observation()
        runtime = SimpleNamespace(DOCKER=['docker'], TARGET='fixed-target', TARGET_CONFIG='config',
            TARGET_MANIFEST='manifest', command=Mock(), inspect_image=Mock(return_value={}),
            cleanup=Mock(return_value=True))
        inventory = SimpleNamespace(now=lambda: 'test', registry_identity=Mock(return_value={
            'platform_manifest_digest': 'manifest', 'config_digest': 'config'}))
        modules = dict(runtime_smoke=runtime, env_probe=inventory, build_container_probe=worker,
            install_container_probe=installer, install_probe=install_host,
            dependency_probe=dependency_host, dependency_container_probe=dependency,
            source_container_probe=source, rust_install_probe=rust_host, rust_install_container_probe=rust_worker)
        original_stat = os.stat
        def socket_stat(path, *args, **kwargs):
            if path == '/var/run/docker.sock':
                return SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=0)
            return original_stat(path, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'result.json'
            with patch.object(host, 'load', side_effect=modules.__getitem__), \
                    patch.object(rust_host, 'profile', return_value=dependency), \
                    patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': host.BRANCH}), \
                    patch.object(host.platform, 'system', return_value='Linux'), \
                    patch.object(host.platform, 'machine', return_value='x86_64'), \
                    patch.object(host.os, 'stat', side_effect=socket_stat), \
                    patch.object(host.subprocess, 'run', return_value=SimpleNamespace(
                        stdout=json.dumps(value), stderr='', returncode=3)) as docker, patch('builtins.print'):
                result = host.main(['--output', str(target), '--allow-pull', '--allow-install',
                    '--allow-rust-install', '--allow-ci430-replacements', '--allow-ruby-3412-rust-build', '--allow-memory-diagnostic', '--ephemeral-ci'])
            saved = json.loads(target.read_text())
        self.assertEqual(result, 3)
        self.assertEqual(saved['status'], 'INCOMPLETE')
        self.assertIs(saved['cleanup_confirmed'], True)
        self.assertIs(saved['phase1_complete'], False)
        self.assertEqual(saved['failure']['partial_measurements']['resources'], value['resources'])
        docker.assert_called_once()
        runtime.cleanup.assert_called_once()


class HostTests(unittest.TestCase):
    def success_fixture(self):
        names = ['configure-negative', 'configure', 'make', 'install', 'runtime']
        names += ['command-' + n for n in worker.COMMANDS] + ['ri-String']
        return {'schema': worker.SCHEMA, 'status': worker.SUCCESS, 'stage': 'finished',
            'condition': {'ruby': '3.4.12', 'prefix': '/opt/ruby', 'documentation': True,
                          'rust': True, 'make_jobs': 1}, 'configure_argv': list(worker.CONFIGURE),
            'p1_04_complete': False, 'phase1_complete': False, 'role_verified': False,
            'idempotence_verified': False, 'full_workspace_retained': False,
            'ruby_build_verified': True, 'unknown_option_rejected': True,
            'rust_present_after_dependencies': True, 'public_commands_unchanged': True,
            'rpm_and_repo_state_unchanged_by_build': True, 'ci_container_cleanup_required': True,
            'elapsed_seconds': 600, 'dependencies': dependency_fixture(), 'runtime': runtime_fixture(),
            'source': {'version': '3.4.12', 'sha256': worker.SOURCE_SHA,
                'sha256_expected': worker.SOURCE_SHA, 'checksum_match': True, 'http_status': 200,
                'extraction_verified': True, 'archive': {'status': 'PASSED', 'gzip_eof_verified': True},
                'redirect_policy': 'no_redirect_followed', 'bytes': 23000000},
            'public_before': dict.fromkeys(range(18), 'absent'),
            'public_after': dict.fromkeys(range(18), 'absent'),
            'commands': [{'name': n, 'path': '/opt/ruby/bin/' + n, 'returncode': 0} for n in worker.COMMANDS],
            'build_settings': {'USE_YJIT': 0, 'USE_RJIT': 0, 'configure_summary_jit_disabled': True,
                'makefile_values': {'prefix': '/opt/ruby', 'ENABLE_SHARED': 'yes', 'YJIT_SUPPORT': 'no',
                                   'RJIT_SUPPORT': 'no', 'DOCTARGETS': 'rdoc nodoc',
                                   'INSTALLDOC': 'all', 'EXTOUT': '.ext'}},
            'documentation': {'enabled': True, 'system_dir': '/opt/ruby/share/ri/3.4.0/system',
                              'standard_String_verified': True, 'other_stores_disabled': True},
            'runs': [{'name': n, 'returncode': 1 if n == 'configure-negative' else 0,
                      'elapsed_seconds': 1, 'bytes': 10, 'sha256': 'a' * 64, 'tail': 'diagnostic'} for n in names],
            'resources': {'sample_count': 10, 'memory_events': None, 'memory_phases': phase_fixture()},
            'prefix_size': {'allocated_bytes': 1000000}}

    def test_complete_result_passes_and_changed_contract_stops(self):
        fixture = self.success_fixture()
        host.validate(fixture, PLAN, worker, installer, install_host, dependency_host, dependency)
        for key, value in (('role_verified', True), ('idempotence_verified', True),
                           ('unknown_option_rejected', False), ('configure_argv', []),
                           ('commands', []), ('documentation', {}), ('runs', [])):
            row = copy.deepcopy(fixture)
            row[key] = value
            with self.subTest(key=key), self.assertRaises(host.Stop):
                host.validate(row, PLAN, worker, installer, install_host, dependency_host, dependency)

    def test_rpm_mismatch_invalidates_build_success(self):
        row = self.success_fixture()
        row['dependencies']['all_signatures_verified'] = False
        with self.assertRaises(host.Stop):
            host.validate(row, PLAN, worker, installer, install_host, dependency_host, dependency)

    def test_pipeline_gates_all_flag_combinations(self):
        config = yaml.safe_load((host.ROOT.parents[1] / '.circleci/config.yml').read_text())
        self.assertFalse(config['parameters']['run_p1_build_probe']['default'])
        def evaluate(expr, values):
            if isinstance(expr, str):
                return values.get(expr, expr)
            if 'and' in expr:
                return all(evaluate(item, values) for item in expr['and'])
            if 'not' in expr:
                return not evaluate(expr['not'], values)
            a, b = expr['equal']
            return evaluate(a, values) == evaluate(b, values)
        self.assertFalse(config['parameters']['run_v010_release_checks']['default'])
        self.assertFalse(config['parameters']['run_v020_release_matrix']['default'])
        for branch in (host.BRANCH, 'main', 'feature/example', ''):
            for matrix, release, build, env in itertools.product((False, True), repeat=4):
                with self.subTest(branch=branch, matrix=matrix, release=release, build=build, env=env):
                    values = {'<< pipeline.parameters.run_p1_build_probe >>': build,
                              '<< pipeline.parameters.run_p1_env_probe >>': env,
                              '<< pipeline.parameters.run_v010_release_checks >>': release,
                              '<< pipeline.parameters.run_v020_release_matrix >>': matrix,
                              '<< pipeline.git.branch >>': branch}
                    selected = [name for name, workflow in config['workflows'].items()
                                if isinstance(workflow, dict) and evaluate(workflow['when'], values)]
                    if matrix:
                        expected = ['v020-release-matrix'] if (
                            branch and branch != host.BRANCH and not any((release, build, env))) else []
                    elif release:
                        expected = ['v010-release-checks'] if (
                            branch == host.BRANCH and not build and not env) else []
                    elif branch == host.BRANCH:
                        expected = ['p1-ruby-build-measurement'] if build and not env else (
                            ['p1-environment-measurement'] if env and not build else [])
                    else:
                        expected = ['build'] if not env and not build else []
                    self.assertEqual(selected, expected)
                    if selected and selected[0].startswith('p1-'):
                        self.assertEqual(len(config['workflows'][selected[0]]['jobs']), 1)
        jobs = config['workflows']['v010-release-checks']['jobs']
        self.assertEqual([next(iter(job)) for job in jobs],
                         ['v010-static-and-probes', 'v010-lint-controls'])
        for job in jobs:
            self.assertEqual(next(iter(job.values()))['filters']['tags']['ignore'], '/.*/')

    def test_missing_permission_does_not_open_output_or_call_docker(self):
        with patch.object(host.os, 'open') as output, patch.object(host.subprocess, 'run') as run, \
                patch('builtins.print'):
            self.assertEqual(host.main(['--output', '/unused']), 3)
        output.assert_not_called()
        run.assert_not_called()

    def test_container_has_no_host_mounts_privilege_or_tmpfs(self):
        argv = host.arguments(SimpleNamespace(DOCKER=['docker'], TARGET_CONFIG='sha256:test'), 'name', 'id')
        for option in ('--privileged', '--mount', '-v', '--tmpfs'):
            self.assertNotIn(option, argv)
        self.assertEqual(argv[argv.index('--memory') + 1], '2g')
        self.assertEqual(argv[argv.index('--memory-swap') + 1], '2g')
        self.assertIn('RUBY_P1_BUILD_PROBE=r39', argv)

    def test_hash_checked_helpers_and_bundle_compile(self):
        for filename in host.HELPERS:
            host.load(filename[:-3])
        text = host.bundle(json.dumps(PLAN))
        compile(text, '<bundle>', 'exec')
        self.assertIn('raise SystemExit(main(_source, _installer, _dependency, _expected, _rust_worker))', text)

    def test_changed_helper_is_rejected(self):
        with patch.dict(host.HELPERS, {'env_probe.py': '0' * 64}), \
                self.assertRaisesRegex(host.Stop, 'HELPER_CHANGED'):
            host.load('env_probe')

    def test_incomplete_worker_cannot_pass(self):
        with self.assertRaisesRegex(host.Stop, 'BUILD_WORKER_SCHEMA'):
            host.validate({'schema': worker.SCHEMA, 'status': 'INCOMPLETE'}, PLAN, worker,
                          installer, install_host, dependency_host, dependency)

    def test_failure_reason_is_filtered(self):
        result = host.diagnostics({'schema': worker.SCHEMA, 'reason': 'https://user:secret@example.invalid',
                                   'stage': 'configure'})
        self.assertNotIn('reason', result)
        self.assertEqual(result['stage'], 'configure')


if __name__ == '__main__':
    unittest.main()
