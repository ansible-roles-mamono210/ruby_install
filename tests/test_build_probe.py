"""Offline boundary tests for r30; these are not Ruby build or CI results."""
import copy
import gzip
import hashlib
import io
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

from test_install_probe import module, fixture as dependency_fixture, PLAN, host as install_host
from test_archive_audit import entry, valid_entries, tar_bytes

worker = module('build_container_probe')
host = module('build_probe')
source = module('source_container_probe')
installer = module('install_container_probe')
dependency = module('dependency_container_probe')
dependency_host = module('dependency_probe')


def runtime_fixture():
    return {'version': '3.4.12', 'ruby': '/opt/ruby-3.4.12-docs-off/bin/ruby', 'prefix': '/opt/ruby-3.4.12-docs-off',
            'shared': 'yes', 'yjit_build': 'no', 'rjit_build': 'no',
            'jit': {'YJIT': False, 'RJIT': 'absent'},
            'shared_libraries': ['/opt/ruby-3.4.12-docs-off/lib/libruby.so.3.4.12'],
            'ri_system': '/opt/ruby-3.4.12-docs-off/share/ri/3.4.0/system',
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
            self.assertEqual(worker.main(source, installer, dependency, PLAN), 3)
        execute.assert_not_called()
        self.assertEqual(json.loads(printed.call_args.args[0])['reason'], 'WORKSPACE_NOEXEC')


class SettingsTests(unittest.TestCase):
    def make_settings(self, directory, yjit=0, docs='nodoc nodoc'):
        root = Path(directory)
        (root / 'Makefile').write_text('prefix = /opt/ruby-3.4.12-docs-off\nENABLE_SHARED = yes\n'
            'YJIT_SUPPORT=no\nRJIT_SUPPORT = no\nDOCTARGETS = ' + docs +
            '\nINSTALLDOC = nodoc\nEXTOUT = .ext\n')
        header = root / '.ext/include/x86_64-linux/ruby/config.h'
        header.parent.mkdir(parents=True)
        header.write_text('#define USE_YJIT ' + str(yjit) + '\n#define USE_RJIT 0\n')
        log = root / 'configure.log'
        log.write_text('   * YJIT support:        no\n   * RJIT support:        no\n'
                       '   * install doc:         no\n')
        return log

    def test_summary_makefile_header_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            result = worker.build_settings(Path(directory), self.make_settings(directory))
        self.assertEqual(result['USE_RJIT'], 0)

    def test_enabled_macro_fails_even_with_disabled_summary(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(worker.Stop, 'JIT_BUILD_ENABLED'):
            worker.build_settings(Path(directory), self.make_settings(directory, yjit=1))

    def test_docs_enabled_fails(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(worker.Stop, 'BUILD_SETTING_MISMATCH'):
            worker.build_settings(Path(directory), self.make_settings(directory, docs='rdoc nodoc'))

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
        argv = worker.documentation_arguments('/opt/ruby-3.4.12-docs-off/share/ri/3.4.0/system')
        selected = next(arg.split('=', 1)[1] for arg in argv if arg.startswith('--format='))
        self.assertIn(selected, formats)
        self.assertNotIn('plain', formats)  # The failure seen in the real CI run.

    def test_documentation_lookup_keeps_only_the_requested_store(self):
        docs = '/opt/ruby-3.4.12-docs-off/share/ri/3.4.0/system'
        argv = worker.documentation_arguments(docs)
        self.assertEqual(argv[0], '/opt/ruby-3.4.12-docs-off/bin/ri')
        self.assertEqual([arg for arg in argv if arg.startswith('--doc-dir=')], ['--doc-dir=' + docs])
        self.assertIn('--no-standard-docs', argv)
        self.assertIn('--no-pager', argv)
        self.assertEqual(argv[-1], 'String')
        for extra_store in ('--system', '--site', '--home', '--gems'):
            self.assertNotIn(extra_store, argv)


class DocsOffCustomPrefixTests(unittest.TestCase):
    def test_fixed_condition_disables_docs_with_custom_prefix(self):
        self.assertEqual(worker.PREFIX, '/opt/ruby-3.4.12-docs-off')
        self.assertIn('--prefix=' + worker.PREFIX, worker.CONFIGURE)
        self.assertIn('--disable-install-doc', worker.CONFIGURE)
        self.assertIn('--disable-yjit', worker.CONFIGURE)
        self.assertIn('--disable-rjit', worker.CONFIGURE)
        self.assertNotIn('--enable-install-doc', worker.CONFIGURE)
        self.assertNotIn('--enable-install-rdoc', worker.CONFIGURE)
        self.assertIn('ri', worker.COMMANDS)
        self.assertIn('rdoc', worker.COMMANDS)

    def test_install_target_and_output_location_must_match(self):
        for old, new in (('INSTALLDOC = nodoc', 'INSTALLDOC = all'),
                         ('EXTOUT = .ext', 'EXTOUT = /elsewhere')):
            with self.subTest(new=new), tempfile.TemporaryDirectory() as directory:
                log = SettingsTests().make_settings(directory)
                path = Path(directory) / 'Makefile'
                path.write_text(path.read_text().replace(old, new))
                with self.assertRaisesRegex(worker.Stop, 'BUILD_SETTING_MISMATCH'):
                    worker.build_settings(Path(directory), log)

    def test_configure_summary_must_disable_documentation(self):
        with tempfile.TemporaryDirectory() as directory:
            log = SettingsTests().make_settings(directory)
            log.write_text(log.read_text().replace('install doc:         no', 'install doc:         rdoc'))
            with self.assertRaisesRegex(worker.Stop, 'DOCUMENTATION_SUMMARY_MISMATCH'):
                worker.build_settings(Path(directory), log)

    def test_no_doc_outputs_or_store_passes_without_ri_lookup(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(worker, 'PREFIX', directory), \
                patch.object(worker, 'run') as run:
            build = Path(directory) / 'build'
            build.mkdir()
            runtime = {'ri_system': directory + '/share/ri/3.4.0/system'}
            row = worker.documentation_off(build, runtime)
        self.assertIs(row['enabled'], False)
        self.assertIs(row['system_store_absent'], True)
        self.assertIs(row['standard_lookup_performed'], False)
        run.assert_not_called()

    def test_generated_documentation_rejected_in_each_known_output(self):
        for relative in ('.ext/rdoc', '.ext/html', 'doc/capi'):
            for kind in ('directory', 'file', 'dangling_symlink'):
                with self.subTest(relative=relative, kind=kind), tempfile.TemporaryDirectory() as directory:
                    build = Path(directory) / 'build'
                    target = build / relative
                    target.parent.mkdir(parents=True)
                    if kind == 'directory':
                        target.mkdir()
                    elif kind == 'file':
                        target.write_text('unexpected documentation')
                    else:
                        target.symlink_to('missing')
                    with self.assertRaisesRegex(worker.Stop, 'DOCUMENTATION_GENERATED'):
                        worker.documentation_off(build, runtime_fixture())

    def test_installed_standard_documentation_rejected(self):
        for kind in ('directory', 'file', 'dangling_symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory, \
                    patch.object(worker, 'PREFIX', directory):
                docs = Path(directory) / 'share/ri/3.4.0/system'
                docs.parent.mkdir(parents=True)
                if kind == 'directory':
                    docs.mkdir()
                elif kind == 'file':
                    docs.write_text('unexpected documentation')
                else:
                    docs.symlink_to('missing')
                with self.assertRaisesRegex(worker.Stop, 'DOCUMENTATION_INSTALLED'):
                    worker.documentation_off(Path(directory) / 'build', {'ri_system': str(docs)})

    def test_external_documentation_path_cannot_hide_installed_store(self):
        with tempfile.TemporaryDirectory() as directory:
            for bad in ('/opt/ruby/share/ri/3.4.0/system', worker.PREFIX + '/share/ri/../missing'):
                with self.subTest(path=bad), self.assertRaisesRegex(worker.Stop, 'DOCUMENTATION_PATH'):
                    worker.documentation_off(Path(directory), {'ri_system': bad})

    def test_default_prefix_runtime_cannot_pass_custom_condition(self):
        row = runtime_fixture()
        row = json.loads(json.dumps(row).replace(worker.PREFIX, '/opt/ruby'))
        with self.assertRaisesRegex(worker.Stop, 'RUNTIME_IDENTITY'):
            worker.validate_runtime(row)

    def test_shebang_uses_exact_custom_ruby_and_escapes_dots(self):
        worker.validate_shebang('#!' + worker.PREFIX + '/bin/ruby\n')
        for wrong in ('/opt/ruby/bin/ruby', '/usr/bin/env ruby',
                      worker.PREFIX.replace('.', 'X') + '/bin/ruby',
                      worker.PREFIX + '/bin/ruby-other'):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(worker.Stop, 'COMMAND_EXTERNAL_RUBY'):
                worker.validate_shebang('#!' + wrong + '\n')

    def test_ci_invokes_new_condition_and_old_flag_is_rejected(self):
        config = yaml.safe_load((host.ROOT.parents[1] / '.circleci/config.yml').read_text())
        command = config['jobs']['p1-ruby-build']['steps'][1]['run']['command']
        self.assertIn('--allow-ruby-3412-docs-off-build', command)
        self.assertNotIn('--allow-ruby-3412-build', command)
        with patch.object(host.os, 'open') as output, \
                patch.object(host.subprocess, 'run') as run, patch('sys.stderr', io.StringIO()):
            with self.assertRaises(SystemExit):
                host.main(['--output', '/unused', '--allow-ruby-3412-build'])
        output.assert_not_called()
        run.assert_not_called()

    def test_host_rejects_docs_on_and_missing_custom_prefix_evidence(self):
        fixture = HostTests().success_fixture()
        for update in ({'condition': dict(fixture['condition'], documentation=True)},
                       {'condition': dict(fixture['condition'], prefix='/opt/ruby')},
                       {'default_prefix_absent': False}):
            row = dict(fixture, **update)
            with self.subTest(update=update), self.assertRaises(host.Stop):
                host.validate(row, PLAN, worker, installer, install_host, dependency_host, dependency)

    def test_host_requires_all_documentation_evidence(self):
        for key, value in (('enabled', True), ('system_store_absent', False),
                           ('generated_outputs_absent', []), ('standard_lookup_performed', True),
                           ('system_dir', '/opt/ruby/share/ri/3.4.0/system'),
                           ('enabled', 0), ('system_store_absent', 1), ('standard_lookup_performed', 0)):
            row = HostTests().success_fixture()
            row['documentation'][key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(host.Stop, 'BUILD_DOCUMENTATION_SCHEMA'):
                host.validate(row, PLAN, worker, installer, install_host, dependency_host, dependency)

    def test_host_rejects_unplanned_documentation_lookup(self):
        row = HostTests().success_fixture()
        row['runs'].append(dict(row['runs'][-1], name='ri-String'))
        with self.assertRaisesRegex(host.Stop, 'BUILD_RUNS_SCHEMA'):
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
            self.assertEqual(worker.main(source, installer, dependency, PLAN), 3)
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
            self.assertEqual(worker.main(source, installer, dependency, PLAN), 3)
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
            source_container_probe=source)
        original_stat = os.stat
        def socket_stat(path, *args, **kwargs):
            if path == '/var/run/docker.sock':
                return SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=0)
            return original_stat(path, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'result.json'
            with patch.object(host, 'load', side_effect=modules.__getitem__), \
                    patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': host.BRANCH}), \
                    patch.object(host.platform, 'system', return_value='Linux'), \
                    patch.object(host.platform, 'machine', return_value='x86_64'), \
                    patch.object(host.os, 'stat', side_effect=socket_stat), \
                    patch.object(host.subprocess, 'run', return_value=SimpleNamespace(
                        stdout=json.dumps(value), stderr='', returncode=3)) as docker, patch('builtins.print'):
                result = host.main(['--output', str(target), '--allow-pull', '--allow-install',
                    '--allow-ci416-replacements', '--allow-ruby-3412-docs-off-build', '--ephemeral-ci'])
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
        names += ['command-' + n for n in worker.COMMANDS]
        return {'schema': worker.SCHEMA, 'status': worker.SUCCESS, 'stage': 'finished',
            'condition': {'ruby': '3.4.12', 'prefix': '/opt/ruby-3.4.12-docs-off', 'documentation': False,
                          'rust': False, 'make_jobs': 1}, 'configure_argv': list(worker.CONFIGURE),
            'p1_04_complete': False, 'phase1_complete': False, 'role_verified': False,
            'idempotence_verified': False, 'full_workspace_retained': False,
            'ruby_build_verified': True, 'unknown_option_rejected': True,
            'rust_absent_after_dependencies': True, 'public_commands_unchanged': True,
            'rpm_and_repo_state_unchanged_by_build': True, 'ci_container_cleanup_required': True,
            'default_prefix_absent': True,
            'elapsed_seconds': 600, 'dependencies': dependency_fixture(), 'runtime': runtime_fixture(),
            'source': {'version': '3.4.12', 'sha256': worker.SOURCE_SHA,
                'sha256_expected': worker.SOURCE_SHA, 'checksum_match': True, 'http_status': 200,
                'extraction_verified': True, 'archive': {'status': 'PASSED', 'gzip_eof_verified': True},
                'redirect_policy': 'no_redirect_followed', 'bytes': 23000000},
            'public_before': dict.fromkeys(range(18), 'absent'),
            'public_after': dict.fromkeys(range(18), 'absent'),
            'commands': [{'name': n, 'path': '/opt/ruby-3.4.12-docs-off/bin/' + n, 'returncode': 0} for n in worker.COMMANDS],
            'build_settings': {'USE_YJIT': 0, 'USE_RJIT': 0, 'configure_summary_jit_disabled': True,
                'makefile_values': {'prefix': '/opt/ruby-3.4.12-docs-off', 'ENABLE_SHARED': 'yes', 'YJIT_SUPPORT': 'no',
                                   'RJIT_SUPPORT': 'no', 'DOCTARGETS': 'nodoc nodoc',
                                   'INSTALLDOC': 'nodoc', 'EXTOUT': '.ext'}},
            'documentation': {'enabled': False, 'system_dir': '/opt/ruby-3.4.12-docs-off/share/ri/3.4.0/system',
                              'system_store_absent': True,
                              'generated_outputs_absent': ['.ext/rdoc', '.ext/html', 'doc/capi'],
                              'standard_lookup_performed': False},
            'runs': [{'name': n, 'returncode': 1 if n == 'configure-negative' else 0,
                      'elapsed_seconds': 1, 'bytes': 10, 'sha256': 'a' * 64, 'tail': 'diagnostic'} for n in names],
            'resources': {'sample_count': 10}, 'prefix_size': {'allocated_bytes': 1000000}}

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
        with self.assertRaises(install_host.Stop):
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
        for branch in (host.BRANCH, 'main'):
            for build in (False, True):
                for env in (False, True):
                    values = {'<< pipeline.parameters.run_p1_build_probe >>': build,
                              '<< pipeline.parameters.run_p1_env_probe >>': env,
                              '<< pipeline.git.branch >>': branch}
                    selected = [name for name, workflow in config['workflows'].items()
                                if isinstance(workflow, dict) and evaluate(workflow['when'], values)]
                    if branch == host.BRANCH:
                        expected = ['p1-ruby-build-measurement'] if build and not env else (
                            ['p1-environment-measurement'] if env and not build else [])
                        self.assertEqual(selected, expected)
                        if selected:
                            self.assertEqual(len(config['workflows'][selected[0]]['jobs']), 1)
                    else:
                        self.assertEqual(selected, ['build'] if not env and not build else [])

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
        self.assertIn('RUBY_P1_BUILD_PROBE=r30', argv)

    def test_hash_checked_helpers_and_bundle_compile(self):
        for filename in host.HELPERS:
            host.load(filename[:-3])
        text = host.bundle(json.dumps(PLAN))
        compile(text, '<bundle>', 'exec')
        self.assertIn('raise SystemExit(main(_source, _installer, _dependency, _expected))', text)

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
