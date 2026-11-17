#!/usr/bin/env python3
"""Lint the actual defaults/vars bytes under an explicit ruby_install role path."""
import argparse
import base64
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile

SCHEMA = 'ruby-role-variable-check-r47'
CONFIG = '---\nwarn_list: []\nskip_list: []\n'
YAML_CONFIG = '''---
extends: default
rules:
  comments:
    min-spaces-from-content: 1
  comments-indentation: disable
  braces:
    max-spaces-inside: 1
  octal-values:
    forbid-implicit-octal: true
    forbid-explicit-octal: true
  line-length: disable
'''
REASONS = ('SOURCE_UNAVAILABLE', 'SOURCE_SYMLINK', 'SOURCE_SPECIAL_FILE',
           'SOURCE_PATH', 'SOURCE_LIMIT', 'SOURCE_CHANGED', 'NO_VARIABLE_FILES',
           'INVALID_SNAPSHOT', 'INVALID_UTF8', 'INLINE_SUPPRESSION',
           'INVALID_VARIABLE_MAPPING', 'LINT_VERSION', 'LINT_TIMEOUT',
           'LINT_OUTPUT', 'LINT_DIAGNOSTICS', 'LINT_STDERR', 'LINT_EXIT',
           'STAGED_INPUT_CHANGED', 'CLEANUP_UNCONFIRMED', 'CHECK_FAILED')
MAX_FILE = 256 * 1024
MAX_TOTAL = 4 * 1024 * 1024


class Stop(Exception):
    pass


def need(value, reason):
    if not value:
        raise Stop(reason)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def collect(source):
    """Open each child relative to a directory FD; never follow links."""
    files, total = {}, 0

    def visit(fd, relative):
        nonlocal total
        for name in sorted(os.listdir(fd)):
            need(bool(re.fullmatch(r'[A-Za-z0-9_.-]+', name)) and not name.startswith('.'), 'SOURCE_PATH')
            path = relative + '/' + name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            need(not stat.S_ISLNK(info.st_mode), 'SOURCE_SYMLINK')
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    visit(child, path)
                finally:
                    os.close(child)
                continue
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'SOURCE_SPECIAL_FILE')
            need(Path(name).suffix in ('.yml', '.yaml'), 'SOURCE_PATH')
            need(info.st_size <= MAX_FILE and len(files) < 128, 'SOURCE_LIMIT')
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(file_fd, 'rb') as handle:
                opened = os.fstat(handle.fileno())
                need((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) ==
                     (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns), 'SOURCE_CHANGED')
                content = handle.read(MAX_FILE + 1)
                after = os.fstat(handle.fileno())
                need((opened.st_size, opened.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
                     and len(content) == opened.st_size, 'SOURCE_CHANGED')
            total += len(content)
            need(total <= MAX_TOTAL, 'SOURCE_LIMIT')
            files[path] = base64.b64encode(content).decode('ascii')

    try:
        root = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for directory in ('defaults', 'vars'):
                try:
                    info = os.stat(directory, dir_fd=root, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                need(not stat.S_ISLNK(info.st_mode), 'SOURCE_SYMLINK')
                need(stat.S_ISDIR(info.st_mode), 'SOURCE_SPECIAL_FILE')
                fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
                try:
                    visit(fd, directory)
                finally:
                    os.close(fd)
        finally:
            os.close(root)
    except OSError:
        raise Stop('SOURCE_UNAVAILABLE') from None
    need(bool(files), 'NO_VARIABLE_FILES')
    return files


def decode(snapshot):
    need(type(snapshot) is dict and 0 < len(snapshot) <= 128, 'INVALID_SNAPSHOT')
    result, total = {}, 0
    for name, encoded in sorted(snapshot.items()):
        need(type(name) is str and bool(re.fullmatch(r'(defaults|vars)/[A-Za-z0-9_./-]+\.(yml|yaml)', name))
             and all(part not in ('', '.', '..') and not part.startswith('.') for part in name.split('/'))
             and str(PurePosixPath(name)) == name and type(encoded) is str, 'INVALID_SNAPSHOT')
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            raise Stop('INVALID_SNAPSHOT') from None
        total += len(content)
        need(len(content) <= MAX_FILE and total <= MAX_TOTAL, 'SOURCE_LIMIT')
        try:
            value = content.decode('utf-8')
        except UnicodeError:
            raise Stop('INVALID_UTF8') from None
        need(not re.search(r'#\s*(?:noqa\b|yamllint\s+disable)', value, re.I), 'INLINE_SUPPRESSION')
        import yaml
        try:
            variables = yaml.safe_load(value)
        except yaml.YAMLError:
            raise Stop('INVALID_VARIABLE_MAPPING') from None
        need(type(variables) is dict and bool(variables) and all(type(k) is str for k in variables),
             'INVALID_VARIABLE_MAPPING')
        result[name] = content
    return result


def run_snapshot(snapshot):
    need(metadata.version('ansible-lint') == '26.1.1', 'LINT_VERSION')
    files = decode(snapshot)
    hashes = {name: digest(value) for name, value in files.items()}
    with tempfile.TemporaryDirectory(prefix='ruby-role-vars-') as temporary:
        project = Path(temporary)
        role = project / 'roles/ruby_install'
        for name, value in files.items():
            path = role / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
        config, ignore, ansible = project / '.ansible-lint', project / '.ansible-lint-ignore', project / 'ansible.cfg'
        config.write_text(CONFIG)
        ignore.write_text('')
        ansible.write_text('[defaults]\n')
        (project / '.yamllint').write_text(YAML_CONFIG)
        inputs = {p: p.read_bytes() for p in (config, ignore, ansible, project / '.yamllint')}
        env = {k: os.environ[k] for k in ('PATH', 'HOME') if k in os.environ}
        executable = os.path.abspath(sys.executable)
        env.update(PATH=str(Path(executable).parent) + os.pathsep + env.get('PATH', ''),
                   LANG='C.UTF-8', PYTHONDONTWRITEBYTECODE='1', ANSIBLE_NOCOLOR='1',
                   ANSIBLE_CONFIG=str(ansible), ANSIBLE_HOME=str(project / 'ansible-home'),
                   XDG_CACHE_HOME=str(project / 'cache'), ANSIBLE_LOCAL_TEMP=str(project / 'ansible-tmp'),
                   ANSIBLE_GALAXY_CACHE_DIR=str(project / 'galaxy-cache'))
        args = [executable, '-B', '-m', 'ansiblelint', '--offline', '--nocolor', '--format', 'json',
                '--project-dir', str(project), '--config-file', str(config), '--ignore-file', str(ignore)]
        args.extend('roles/ruby_install/' + name for name in files)
        try:
            process = subprocess.run(args, cwd=project, env=env, capture_output=True, text=True,
                                     timeout=30, check=False)
        except subprocess.TimeoutExpired:
            raise Stop('LINT_TIMEOUT') from None
        need(len(process.stdout.encode()) <= 1024 * 1024 and len(process.stderr.encode()) <= 65536, 'LINT_OUTPUT')
        try:
            issues = json.loads(process.stdout)
        except ValueError:
            raise Stop('LINT_OUTPUT') from None
        need(type(issues) is list, 'LINT_OUTPUT')
        diagnostics = []
        for item in issues:
            need(type(item) is dict and type(item.get('check_name')) is str
                 and type(item.get('location')) is dict and type(item.get('description')) is str,
                 'LINT_DIAGNOSTICS')
            path = item['location'].get('path')
            need(type(path) is str and path.startswith('roles/ruby_install/')
                 and path.removeprefix('roles/ruby_install/') in files, 'LINT_DIAGNOSTICS')
            diagnostics.append({'rule': item['check_name'], 'path': path.removeprefix('roles/ruby_install/'),
                                'description': item['description'], 'location': item['location']})
        expected_exit = 2 if issues else 0
        need(process.returncode == expected_exit, 'LINT_EXIT')
        # Match the whole summary, so extra warnings or unrelated output cannot pass.
        count = str(len(files))
        suffix = (' in ' + count + ' files processed of ' + count + ' encountered. '
                  "Last profile that met the validation criteria was '")
        if not issues:
            need(process.stderr == '\nPassed: 0 failure(s), 0 warning(s)' + suffix + "production'.\n", 'LINT_STDERR')
        else:
            pattern = (r'Read documentation for instructions on how to ignore specific rule violations\.\n\n'
                       r'# Rule Violation Summary\n\n(?P<rows>(?:  [0-9]+ [a-z][a-z0-9-]* '
                       r'profile:[a-z]+ tags:[a-z0-9,-]+\n)+)\nFailed: '
                       + str(len(issues)) + r' failure\(s\), 0 warning\(s\)' + re.escape(suffix)
                       + r"[a-z]+'\.\n")
            match = re.fullmatch(pattern, process.stderr)
            need(match is not None, 'LINT_STDERR')
            need(sum(int(line.split()[0]) for line in match['rows'].splitlines()) == len(issues), 'LINT_STDERR')
        need(all((role / name).read_bytes() == value for name, value in files.items())
             and all(p.read_bytes() == value for p, value in inputs.items()), 'STAGED_INPUT_CHANGED')
    need(not project.exists(), 'CLEANUP_UNCONFIRMED')
    return {'schema': SCHEMA, 'status': 'VIOLATIONS_FOUND' if issues else 'PASSED',
            'exit_code': expected_exit, 'source_sha256': hashes, 'diagnostics': diagnostics,
            'stdout_sha256': digest(process.stdout.encode()), 'stderr_sha256': digest(process.stderr.encode()),
            'staged_inputs_unchanged': True, 'temporary_directory_removed': True,
            'scope': 'defaults_and_vars_only', 'full_role_lint_passed': False}


def check(source):
    snapshot = collect(source)
    result = run_snapshot(snapshot)
    need(collect(source) == snapshot, 'SOURCE_CHANGED')
    result['source_inputs_unchanged'] = True
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    args = parser.parse_args(argv)
    try:
        result = check(args.source)
    except Stop as error:
        result = {'status': 'INCOMPLETE', 'reason': str(error), 'exit_code': 3}
    except Exception:
        result = {'status': 'INCOMPLETE', 'reason': 'CHECK_FAILED', 'exit_code': 3}
    print(json.dumps(result, sort_keys=True))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
