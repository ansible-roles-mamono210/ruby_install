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
import time



def warning_facts(stderr):
    """Fixed classifications only. No matched substring or arbitrary path is copied."""
    lower = stderr.lower()
    patterns = {
        'READ_ONLY_FILESYSTEM': (b'read-only file system', b'[errno 30]'),
        'PERMISSION_DENIED': (b'permission denied', b'[errno 13]'),
        'NO_USABLE_COLLECTION_PATH': (b'none of the provided paths were usable',),
        'UNKNOWN_CLI_OPTION': (b'unrecognized arguments:', b'no such option:'),
        'PYTHON_IMPORT_ERROR': (b'modulenotfounderror:', b'importerror:'),
        'DRIVER_LOAD_ERROR': (b'failed to load', b'skipped loading plugin'),
    }
    paths = {
        'CIRCLECI_ANSIBLE_HOME': b'/home/circleci/.ansible',
        'CIRCLECI_CACHE': b'/home/circleci/.cache',
        'ROOT_ANSIBLE_HOME': b'/root/.ansible',
        'ROOT_CACHE': b'/root/.cache',
        'TMP_GALAXY_CACHE': b'/tmp/ansible-galaxy-cache',
        'TMP_ANSIBLE_LOCAL': b'/tmp/ansible-local',
        'TMP_CACHE': b'/tmp/cache',
        'VAR_LOG_ANSIBLE': b'/var/log/ansible.log',
    }
    return {
        'stderr_hints': sorted(code for code, needles in patterns.items()
                               if any(needle in lower for needle in needles)),
        'stderr_path_classes': sorted(code for code, value in paths.items() if value in stderr),
        'stderr_review_required': bool(stderr),
    }

def collection_command():
    """Return stdout for parsing, but persist only allowlisted failure metadata."""
    started = time.monotonic()
    result = {'state': 'OS_ERROR', 'returncode': None, 'errno': None,
              'stdout_bytes': 0, 'stderr_bytes': 0, 'stderr_hints': []}
    stdout = stderr = b''
    try:
        process = subprocess.run(
            ['ansible-galaxy', 'collection', 'list', '--format', 'json'],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=30,
            env=os.environ.copy(), check=False)
        stdout, stderr = process.stdout, process.stderr
        result.update(state='EXITED', returncode=process.returncode)
    except subprocess.TimeoutExpired as exc:
        result['state'] = 'TIMEOUT'
        stdout, stderr = exc.stdout or b'', exc.stderr or b''
    except OSError as exc:
        result['errno'] = exc.errno
    result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
    result['stdout_bytes'], result['stderr_bytes'] = len(stdout), len(stderr)
    result.update(warning_facts(stderr))
    if len(stdout) > 8 * 1024 * 1024 or len(stderr) > 8 * 1024 * 1024:
        result['state'] = 'OUTPUT_TOO_LARGE'
    text = stdout.decode('utf-8', errors='replace') if (
        result['state'] == 'EXITED' and result['returncode'] == 0) else ''
    return result, text


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
        diagnostic, text = collection_command()
        out['collections_diagnostic'] = diagnostic
        if diagnostic['state'] == 'EXITED' and diagnostic['returncode'] == 0:
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
    if os.environ.get('RUBY_P1_CONTROLLER_CHECKS') == '1':
        out['controller_checks'] = controller_checks()
    print(json.dumps(out, ensure_ascii=False, sort_keys=True))


if __name__ == '__main__':
    main()
