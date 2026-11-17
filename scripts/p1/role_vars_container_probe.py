"""Check actual Role variable bytes and negative controls in the fixed lint image."""
import base64
import copy
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import socket
import tempfile
import time

SCHEMA = 'ruby-p1-role-vars-controls-r47'
SUCCESS = 'REAL_VARIABLE_SOURCE_CONTROLS_VERIFIED'
PACKAGES = ('ansible-lint', 'ansible-core', 'ansible-compat', 'ruamel.yaml', 'yamllint')
RENAMES = {'workspace': 'ruby_install_workspace', 'ruby_download_url': 'ruby_install_download_url',
           'ruby_version': 'ruby_install_version', 'ruby_make_prefix': 'ruby_install_prefix'}
EXPECTED = (
    ('actual_source', 2, ['var-naming[no-role-prefix]'] * 4),
    ('adopted_counterpart', 0, []),
    ('nested_variable', 2, ['var-naming[no-role-prefix]']),
    ('uppercase', 2, ['var-naming[pattern]']),
    ('inline_suppression', 3, 'INLINE_SUPPRESSION'),
    ('empty_source', 3, 'NO_VARIABLE_FILES'),
    ('symlink', 3, 'SOURCE_SYMLINK'),
    ('non_mapping', 3, 'INVALID_VARIABLE_MAPPING'),
)
REASONS = ('SOURCE_BASELINE', 'WORKER_PLATFORM', 'WORKER_ISOLATION', 'CONTROL_MATRIX',
           'SOURCE_CHANGED', 'CLEANUP_UNCONFIRMED', 'WORKER_CHECK_FAILED')


class Stop(Exception):
    pass


def need(condition, reason):
    if not condition:
        raise Stop(reason)


def run(checker, snapshot, source_hash, isolated=False):
    started = time.monotonic()
    need(type(snapshot) is dict and set(snapshot) == {'defaults/main.yml'}, 'SOURCE_BASELINE')
    raw = base64.b64decode(snapshot['defaults/main.yml'], validate=True)
    need(checker.digest(raw) == source_hash, 'SOURCE_BASELINE')
    versions = {name: metadata.version(name) for name in PACKAGES}
    need(versions['ansible-lint'] == '26.1.1', 'WORKER_PLATFORM')
    if isolated:
        need(platform.system() == 'Linux' and platform.machine() == 'x86_64'
             and platform.python_version().startswith('3.14.') and os.geteuid() > 0, 'WORKER_PLATFORM')
        need({n for _, n in socket.if_nameindex()} == {'lo'}
             and bool(os.statvfs('/').f_flag & os.ST_RDONLY)
             and bool(os.statvfs('/tmp').f_flag & os.ST_NOEXEC), 'WORKER_ISOLATION')
    adopted = raw.decode()
    for old, new in RENAMES.items():
        need(adopted.count('\n' + old + ':') == 1, 'SOURCE_BASELINE')
        adopted = adopted.replace('\n' + old + ':', '\n' + new + ':')
    original = copy.deepcopy(snapshot)
    rows = []
    with tempfile.TemporaryDirectory(prefix='ruby-role-controls-') as temporary:
        root = Path(temporary)
        for name, code, expected in EXPECTED:
            source = root / name
            (source / 'defaults').mkdir(parents=True)
            path = source / 'defaults/main.yml'
            path.write_bytes(raw if name == 'actual_source' else adopted.encode())
            if name in ('nested_variable', 'uppercase'):
                extra = source / 'vars/nested/check.yml'
                extra.parent.mkdir(parents=True)
                extra.write_text('---\n' + ('_probe' if name == 'nested_variable' else 'ruby_install_Bad') + ': fixture\n')
            elif name == 'inline_suppression':
                path.write_text('---\nworkspace: fixture  # noqa: var-naming\n')
            elif name == 'empty_source':
                path.unlink()
            elif name == 'symlink':
                path.unlink()
                path.symlink_to(root / 'actual_source/defaults/main.yml')
            elif name == 'non_mapping':
                path.write_text('---\n- fixture\n')
            try:
                result = checker.check(source)
            except checker.Stop as error:
                result = {'status': 'INCOMPLETE', 'reason': str(error), 'exit_code': 3}
            need(result['exit_code'] == code, 'CONTROL_MATRIX')
            if code == 3:
                need(result == {'status': 'INCOMPLETE', 'reason': expected, 'exit_code': 3}, 'CONTROL_MATRIX')
            else:
                need([x['rule'] for x in result['diagnostics']] == expected
                     and result['source_inputs_unchanged'] and result['staged_inputs_unchanged']
                     and result['temporary_directory_removed'] and not result['full_role_lint_passed'], 'CONTROL_MATRIX')
                if name == 'actual_source':
                    need(result['source_sha256'] == {'defaults/main.yml': source_hash}, 'SOURCE_CHANGED')
                    need([x['description'].rsplit('(vars: ', 1)[-1].rstrip(')') for x in result['diagnostics']]
                         == list(RENAMES), 'CONTROL_MATRIX')
                elif name in ('nested_variable', 'uppercase'):
                    need(result['diagnostics'][0]['path'] == 'vars/nested/check.yml', 'CONTROL_MATRIX')
            rows.append({'case': name, 'result': result})
    need(not root.exists() and snapshot == original, 'CLEANUP_UNCONFIRMED')
    return {'schema': SCHEMA, 'status': SUCCESS, 'scope': 'actual_defaults_vars_bytes_and_controls',
            'source_sha256': {'defaults/main.yml': source_hash}, 'cases': rows,
            'packages': versions, 'python': platform.python_version(), 'uid': os.geteuid(),
            'arch': platform.machine(), 'isolation_checked': isolated,
            'temporary_directory_removed': True, 'source_inputs_unchanged': True,
            'elapsed_seconds': round(time.monotonic() - started, 3),
            'actual_source_lint_passed': False, 'full_role_lint_passed': False, 'phase1_complete': False}
