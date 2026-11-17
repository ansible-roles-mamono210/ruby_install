#!/usr/bin/env python3
"""Exercise real ansible-lint on disposable variable-name fixtures, not the Role."""
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import sys
import tempfile
import time

SCHEMA = 'ruby-p1-lint-fixture-r45'
SUCCESS = 'VARIABLE_NAMING_CONTROLS_VERIFIED'
PUBLIC = ('ruby_install_version', 'ruby_install_prefix', 'ruby_install_download_url',
          'ruby_install_download_checksum', 'ruby_install_documentation',
          'ruby_install_create_symlinks', 'ruby_install_symlink_commands',
          'ruby_install_build_jobs', 'ruby_install_workspace', 'ruby_install_keep_build_workspace')
LEGACY = ('workspace', 'ruby_download_url', 'ruby_version', 'ruby_make_prefix')
CASES = (
    ('public_defaults', 'defaults', PUBLIC, None),
    ('public_vars', 'vars', PUBLIC, None),
    ('private_prefixed', 'vars', ('_ruby_install_probe',), None),
    ('legacy_defaults', 'defaults', LEGACY, 'var-naming[no-role-prefix]'),
    ('legacy_vars', 'vars', LEGACY, 'var-naming[no-role-prefix]'),
    ('foreign_prefix', 'defaults', ('other_install_version',), 'var-naming[no-role-prefix]'),
    ('uppercase', 'defaults', ('ruby_install_Bad',), 'var-naming[pattern]'),
    ('private_unprefixed', 'vars', ('_probe',), 'var-naming[no-role-prefix]'),
)
CONFIG = '---\nwarn_list: []\nskip_list: []\n'
PACKAGES = ('ansible-lint', 'ansible-core', 'ansible-compat', 'ruamel.yaml', 'yamllint')
REASONS = ('LINT_VERSION', 'WORKER_PLATFORM', 'WORKER_ISOLATION', 'LINT_TIMEOUT',
           'LINT_OUTPUT_SIZE', 'LINT_JSON', 'LINT_DIAGNOSTICS', 'LINT_EXIT_CODE',
           'LINT_STDERR', 'FIXTURE_CHANGED', 'TEMPORARY_DIRECTORY_RETAINED', 'WORKER_CHECK_FAILED')


class Stop(Exception):
    pass


def need(condition, reason):
    if not condition:
        raise Stop(reason)


def packages():
    result = {name: metadata.version(name) for name in PACKAGES}
    need(result['ansible-lint'] == '26.1.1', 'LINT_VERSION')
    need(all(re.fullmatch(r'[0-9A-Za-z.+-]{1,40}', value) for value in result.values()), 'LINT_VERSION')
    return result


def expected(case):
    name, directory, variables, rule = case
    return [{'rule': rule, 'variable': variable, 'line': line, 'column': 1,
             'path': 'roles/ruby_install/' + directory + '/main.yml', 'severity': 'major'}
            for line, variable in enumerate(variables, 2)] if rule else []


def check_output(process, case):
    need(len(process.stdout.encode()) <= 65536 and len(process.stderr.encode()) <= 16384, 'LINT_OUTPUT_SIZE')
    try:
        values = json.loads(process.stdout)
    except ValueError:
        raise Stop('LINT_JSON') from None
    want = expected(case)
    need(type(values) is list and len(values) == len(want), 'LINT_DIAGNOSTICS')
    observed = []
    for value, row in zip(values, want):
        need(type(value) is dict and set(value) == {'type', 'check_name', 'categories', 'url',
                                                  'severity', 'description', 'fingerprint', 'location'}, 'LINT_DIAGNOSTICS')
        message = ('Variables names from within roles should use ruby_install_ as a prefix.'
                   if row['rule'] == 'var-naming[no-role-prefix]' else
                   'Variables names should match ^[a-z_][a-z0-9_]*$ regex. (' + row['variable'] + ')')
        need(value['type'] == 'issue' and value['check_name'] == row['rule']
             and value['categories'] == ['idiom'] and value['severity'] == 'major'
             and value['url'] == 'https://docs.ansible.com/projects/lint/rules/var-naming/'
             and value['description'] == message + ' (vars: ' + row['variable'] + ')'
             and type(value['fingerprint']) is str and re.fullmatch('[0-9a-f]{64}', value['fingerprint'])
             and json.dumps(value['location'], sort_keys=True) == json.dumps(
                 {'path': row['path'], 'positions': {'begin': {'line': row['line'], 'column': 1}}}, sort_keys=True),
             'LINT_DIAGNOSTICS')
        observed.append(row)
    code = 2 if want else 0
    need(type(process.returncode) is int and process.returncode == code, 'LINT_EXIT_CODE')
    if want:
        stderr = ('Read documentation for instructions on how to ignore specific rule violations.\n\n'
                  '# Rule Violation Summary\n\n  ' + str(len(want)) +
                  " var-naming profile:basic tags:idiom\n\nFailed: " + str(len(want)) +
                  " failure(s), 0 warning(s) in 1 files processed of 1 encountered. "
                  "Last profile that met the validation criteria was 'min'.\n")
    else:
        stderr = ("\nPassed: 0 failure(s), 0 warning(s) in 1 files processed of 1 encountered. "
                  "Last profile that met the validation criteria was 'production'.\n")
    need(process.stderr == stderr, 'LINT_STDERR')
    return {'case': case[0], 'exit_code': code, 'diagnostics': observed,
            'stdout_sha256': hashlib.sha256(process.stdout.encode()).hexdigest(),
            'stderr_sha256': hashlib.sha256(process.stderr.encode()).hexdigest(),
            'stderr_class': 'expected_violation_summary' if want else 'expected_pass_summary'}


def exercise(isolated=False):
    started = time.monotonic()
    versions = packages()
    if isolated:
        need(platform.system() == 'Linux' and platform.machine() == 'x86_64'
             and sys.version_info[:2] == (3, 14) and os.geteuid() > 0, 'WORKER_PLATFORM')
        need({name for _, name in socket.if_nameindex()} == {'lo'}
             and bool(os.statvfs('/').f_flag & os.ST_RDONLY)
             and bool(os.statvfs('/tmp').f_flag & os.ST_NOEXEC), 'WORKER_ISOLATION')
    rows = []
    with tempfile.TemporaryDirectory(prefix='ruby-p1-lint-') as temporary:
        root = Path(temporary)
        for case in CASES:
            project = root / case[0]
            fixture = project / ('roles/ruby_install/' + case[1] + '/main.yml')
            fixture.parent.mkdir(parents=True)
            # These scalar values are inert data; only names are under test.
            fixture.write_text('---\n' + ''.join(name + ': fixture\n' for name in case[2]))
            config, ignore, ansible = project / '.ansible-lint', project / '.ansible-lint-ignore', project / 'ansible.cfg'
            config.write_text(CONFIG)
            ignore.write_text('')
            ansible.write_text('[defaults]\n')
            inputs = {p: p.read_bytes() for p in (fixture, config, ignore, ansible)}
            # Preserve the image user's HOME for user-site packages; all writable caches are explicit.
            env = {k: os.environ[k] for k in ('PATH', 'HOME') if k in os.environ}
            # Collapse '..' without resolving a virtualenv's Python symlink out of that environment.
            executable = os.path.abspath(sys.executable)
            env.update(PATH=str(Path(executable).parent) + os.pathsep + env.get('PATH', ''),
                       LANG='C.UTF-8', PYTHONDONTWRITEBYTECODE='1', ANSIBLE_NOCOLOR='1',
                       ANSIBLE_CONFIG=str(ansible), ANSIBLE_HOME=str(project / 'ansible-home'),
                       ANSIBLE_LOCAL_TEMP=str(project / 'ansible-tmp'), XDG_CACHE_HOME=str(project / 'cache'),
                       ANSIBLE_GALAXY_CACHE_DIR=str(project / 'galaxy-cache'))
            argv = [executable, '-B', '-m', 'ansiblelint', '--offline', '--nocolor', '--format', 'json',
                    '--project-dir', str(project), '--config-file', str(config), '--ignore-file', str(ignore),
                    str(fixture.relative_to(project))]
            try:
                process = subprocess.run(argv, cwd=project, env=env, capture_output=True, text=True,
                                         timeout=20, check=False)
            except subprocess.TimeoutExpired:
                raise Stop('LINT_TIMEOUT') from None
            try:
                rows.append(check_output(process, case))
            except Stop as error:
                error.diagnostic = {'case': case[0], 'exit_code': process.returncode,
                                    'stdout_bytes': len(process.stdout.encode()),
                                    'stderr_bytes': len(process.stderr.encode()),
                                    'stdout_sha256': hashlib.sha256(process.stdout.encode()).hexdigest(),
                                    'stderr_sha256': hashlib.sha256(process.stderr.encode()).hexdigest()}
                raise
            need(all(p.read_bytes() == original for p, original in inputs.items()), 'FIXTURE_CHANGED')
    need(not root.exists(), 'TEMPORARY_DIRECTORY_RETAINED')
    return {'schema': SCHEMA, 'status': SUCCESS, 'scope': 'disposable_variable_files_all_default_rules',
            'packages': versions, 'python': platform.python_version(), 'arch': platform.machine(),
            'uid': os.geteuid(), 'isolation_checked': isolated, 'cases': rows,
            'elapsed_seconds': round(time.monotonic() - started, 3),
            'config_sha256': hashlib.sha256(CONFIG.encode()).hexdigest(),
            'temporary_directory_removed': True, 'fixture_inputs_unchanged': True,
            'role_verified': False, 'full_role_lint_passed': False, 'phase1_complete': False}
