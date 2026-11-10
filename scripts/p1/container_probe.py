"""Inventory-only probe, executed inside a temporary image (Python >= 3.9)."""
import configparser
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys


def os_release():
    result = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            if key in {'ID', 'VERSION_ID', 'PRETTY_NAME'}:
                parsed = shlex.split(value)
                result[key] = parsed[0] if parsed else ''
    return result


def command(args):
    try:
        p = subprocess.run(args, text=True, capture_output=True, timeout=30,
                           env=os.environ.copy(), check=False)
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None, ''


def main():
    out = {'os': os_release(), 'arch': platform.machine(),
           'python': platform.python_version(), 'python_path': sys.executable,
           'uid': os.getuid(), 'packages': {}, 'collections': None,
           'collections_status': 'NOT_AVAILABLE', 'rpm_packages': None,
           'rpm_status': 'NOT_AVAILABLE', 'repo_config': [],
           'repo_status': 'NOT_AVAILABLE', 'tools': {}}
    for name in ['ansible-core', 'ansible', 'molecule', 'molecule-plugins',
                 'ansible-lint', 'docker']:
        try:
            out['packages'][name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            out['packages'][name] = None
    for tool in ['ansible', 'ansible-galaxy', 'molecule', 'ansible-lint',
                 'rpm', 'dnf', 'sudo', 'rustc', 'cargo', 'ruby']:
        out['tools'][tool] = shutil.which(tool)
    out['dnf_python_module_found'] = importlib.util.find_spec('dnf') is not None
    if out['tools']['ansible-galaxy']:
        rc, text = command(['ansible-galaxy', 'collection', 'list', '--format', 'json'])
        if rc == 0:
            try:
                values = json.loads(text)
                rows = []
                for location, collections in values.items():
                    for name, info in collections.items():
                        rows.append({'name': name, 'version': info.get('version'),
                                     'location': location})
                out['collections'] = sorted(rows, key=lambda r: (r['name'], r['location']))
                out['collections_status'] = 'COLLECTED'
            except (ValueError, TypeError, AttributeError):
                out['collections_status'] = 'INVALID_OUTPUT'
        else:
            out['collections_status'] = 'COMMAND_FAILED'
    if out['tools']['rpm']:
        rc, text = command(['rpm', '-qa', '--qf', '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n'])
        if rc == 0:
            rows = [line.split('\t', 1) for line in text.splitlines()]
            if all(len(row) == 2 for row in rows):
                out['rpm_packages'] = sorted(rows)
                out['rpm_status'] = 'COLLECTED'
    repo_dir = Path('/etc/yum.repos.d')
    if repo_dir.is_dir():
        out['repo_status'] = 'CONFIG_ONLY'
        for path in sorted(repo_dir.glob('*.repo')):
            try:
                cfg = configparser.ConfigParser(interpolation=None, strict=False)
                cfg.read_string(path.read_text())
                for section in cfg.sections():
                    out['repo_config'].append({'file': path.name, 'repo_id': section,
                                               'enabled': cfg.get(section, 'enabled', fallback='1')})
            except (OSError, configparser.Error):
                out['repo_status'] = 'PARTIAL'
    print(json.dumps(out, ensure_ascii=False, sort_keys=True))


if __name__ == '__main__':
    main()
