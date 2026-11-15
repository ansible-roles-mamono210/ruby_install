"""Offline boundary tests for r28; these are not Ruby build or CI results."""
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
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
            self.assertEqual(worker.main(source, installer, dependency, PLAN), 3)
        execute.assert_not_called()
        self.assertEqual(json.loads(printed.call_args.args[0])['reason'], 'WORKSPACE_NOEXEC')


class SettingsTests(unittest.TestCase):
    def make_settings(self, directory, yjit=0, docs='rdoc nodoc'):
        root = Path(directory)
        (root / 'Makefile').write_text('prefix = /opt/ruby\nENABLE_SHARED = yes\n'
            'YJIT_SUPPORT=no\nRJIT_SUPPORT = no\nDOCTARGETS = ' + docs + '\n')
        header = root / '.ext/include/x86_64-linux/ruby/config.h'
        header.parent.mkdir(parents=True)
        header.write_text('#define USE_YJIT ' + str(yjit) + '\n#define USE_RJIT 0\n')
        log = root / 'configure.log'
        log.write_text('   * YJIT support:        no\n   * RJIT support:        no\n')
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


class HostTests(unittest.TestCase):
    def success_fixture(self):
        names = ['configure-negative', 'configure', 'make', 'install', 'runtime']
        names += ['command-' + n for n in worker.COMMANDS] + ['ri-String']
        return {'schema': worker.SCHEMA, 'status': worker.SUCCESS, 'stage': 'finished',
            'condition': {'ruby': '3.4.12', 'prefix': '/opt/ruby', 'documentation': True,
                          'rust': False, 'make_jobs': 1}, 'configure_argv': list(worker.CONFIGURE),
            'p1_04_complete': False, 'phase1_complete': False, 'role_verified': False,
            'idempotence_verified': False, 'full_workspace_retained': False,
            'ruby_build_verified': True, 'unknown_option_rejected': True,
            'rust_absent_after_dependencies': True, 'public_commands_unchanged': True,
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
                                   'RJIT_SUPPORT': 'no', 'DOCTARGETS': 'rdoc nodoc'}},
            'documentation': {'enabled': True, 'system_dir': '/opt/ruby/share/ri/3.4.0/system',
                              'standard_String_verified': True, 'other_stores_disabled': True},
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
        self.assertIn('RUBY_P1_BUILD_PROBE=r28', argv)

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
