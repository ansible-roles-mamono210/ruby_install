#!/usr/bin/env python3
"""Read target metadata only. No repository traffic, plugin init or transactions."""
import importlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import sys

SCHEMA = 'ruby-p1-target-offline-r9'
TOKEN = re.compile(r'^[A-Za-z0-9_.:+-]{1,160}$')
TOOLS = ('python3', 'dnf', 'rpm', 'sudo', 'findmnt', 'gcc', 'make')


def os_release():
    result = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            if key in ('ID', 'VERSION_ID', 'PRETTY_NAME'):
                words = shlex.split(value)
                result[key] = words[0] if words else ''
    return result


def mount_flags(text, path):
    """Return only effective flags, not source names or host paths."""
    matches = []
    for line in text.splitlines():
        left, right = line.split(' - ', 1)
        fields = left.split()
        target = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4])
        if path == target or path.startswith(target.rstrip('/') + '/'):
            flags = set(fields[5].split(',')) | set(right.split()[2].split(','))
            matches.append((len(target), {name: name in flags
                                         for name in ('ro', 'noexec', 'nosuid', 'nodev')}))
    if not matches:
        raise ValueError('mount not found')
    maximum = max(length for length, _ in matches)
    winners = [flags for length, flags in matches if length == maximum]
    if len(winners) != 1:
        raise ValueError('ambiguous effective mount')
    return winners[0]


def dnf_configuration(importer=importlib.import_module):
    """DNF configuration access only; never initialize plugins or fill a sack."""
    dnf = importer('dnf')
    rpm = importer('rpm')
    versions = {}
    for name, module in (('dnf', dnf), ('rpm', rpm)):
        value = str(getattr(module, '__version__', ''))
        if not TOKEN.fullmatch(value):
            raise ValueError('missing or invalid module version')
        versions[name] = value
    with dnf.Base() as base:
        base.conf.read()
        # This is an explicit probe override, not an observed image default.
        base.conf.cacheonly = True
        base.read_all_repos()
        rows = []
        for repo in base.repos.values():
            if not isinstance(repo.id, str) or not TOKEN.fullmatch(repo.id):
                raise ValueError('invalid repository id')
            if type(repo.enabled) not in (bool, int) or repo.enabled not in (0, 1):
                raise ValueError('invalid repository enabled flag')
            rows.append({'id': repo.id, 'enabled': bool(repo.enabled)})
        rows.sort(key=lambda row: row['id'])
        if not rows or len({row['id'] for row in rows}) != len(rows):
            raise ValueError('missing or duplicate repositories')
    return {'status': 'IMPORT_AND_CONFIG_ONLY', 'versions': versions,
            'cacheonly_override': True, 'plugins_initialized': False,
            'metadata_loaded': False, 'repositories': rows}


def main():
    report = {'schema': SCHEMA, 'scope': 'restricted_probe_container',
              'status': 'INCOMPLETE', 'errors': []}
    checks = (
        ('platform', lambda: {'os': os_release(), 'arch': platform.machine(),
                             'python': platform.python_version(),
                             'uid': os.getuid(), 'euid': os.geteuid()}),
        ('tools_present', lambda: {name: shutil.which(name) is not None for name in TOOLS}),
        ('mounts', lambda: {name: mount_flags(Path('/proc/self/mountinfo').read_text(), name)
                           for name in ('/', '/tmp')}),
        ('dnf', dnf_configuration),
    )
    for key, function in checks:
        try:
            report[key] = function()
        except Exception:
            # Error text can contain URL credentials; record only the stage.
            report['errors'].append(key + '_UNCONFIRMED')
    if not report['errors']:
        report['status'] = 'COLLECTED'
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
