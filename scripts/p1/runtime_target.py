"""Probe/fixture code for a disposable target only; never run on a real host."""
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import subprocess
import sys

USER = 'ruby_p1_probe'
UID = 29999
RULE = '/etc/sudoers.d/ruby-p1-probe'
COMMANDS = ('ruby', 'gem', 'bundle', 'bundler', 'irb', 'erb', 'rdoc', 'ri', 'rake')


def run(argv):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False)
    if p.returncode or p.stderr or len(p.stdout) > 32768:
        raise ValueError('COMMAND_FAILED')
    return p.stdout


def mount_flags(text, path):
    rows = []
    for line in text.splitlines():
        left, _ = line.split(' - ', 1)
        f = left.split()
        target = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), f[4])
        if path == target or path.startswith(target.rstrip('/') + '/'):
            rows.append((len(target), set(f[5].split(','))))
    if not rows:
        raise ValueError('MOUNT_NOT_FOUND')
    longest = max(n for n, _ in rows)
    values = [flags for n, flags in rows if n == longest]
    if len(values) != 1:
        raise ValueError('MOUNT_AMBIGUOUS')
    return {k: k in values[0] for k in ('ro', 'noexec', 'nosuid', 'nodev')}


def paths():
    path = os.environ.get('PATH', '')
    if not path or len(path) > 2048 or any(ord(c) < 32 for c in path):
        raise ValueError('PATH_INVALID')
    return {'path': path, 'uid': os.getuid(), 'euid': os.geteuid(),
            'commands': {k: shutil.which(k) for k in COMMANDS}}


def baseline():
    if os.getuid() != 0 or os.geteuid() != 0 or platform.python_version() != '3.9.19':
        raise ValueError('BASELINE_MISMATCH')
    # Probe effective sudo PATH, without reading sudoers, sudo -l, or environment lists.
    # The caller supplies this same source through -c. A short child only emits PATH/IDs.
    code = ('import json,os,shutil; print(json.dumps({"path":os.environ.get("PATH", ""),'
            '"uid":os.getuid(),"euid":os.geteuid(),"commands":'
            '{k:shutil.which(k) for k in ' + repr(COMMANDS) + '}}))')
    sudo = json.loads(run(['sudo', '-n', '-H', '/usr/bin/python3', '-I', '-B', '-c', code]))
    if sudo.get('uid') != 0 or sudo.get('euid') != 0:
        raise ValueError('SUDO_IDENTITY')
    if not all(shutil.which(p) for p in ('sudo', 'visudo', 'useradd')):
        raise ValueError('FIXTURE_TOOLS_MISSING')
    text = Path('/proc/self/mountinfo').read_text()
    return {'schema': 'ruby-p1-runtime-baseline-r11', 'direct': paths(), 'sudo_root': sudo,
            'mounts': {p: mount_flags(text, p) for p in ('/', '/tmp')},
            'tools': {p: shutil.which(p) is not None for p in ('sudo', 'visudo', 'useradd')},
            'scope': 'stock_image_docker_exec_root_before_fixture'}


def fixture():
    if os.geteuid() != 0 or Path(RULE).exists() or Path(RULE).is_symlink():
        raise ValueError('FIXTURE_COLLISION')
    for lookup, key in ((pwd.getpwnam, USER), (pwd.getpwuid, UID)):
        try:
            lookup(key)
        except KeyError:
            continue
        raise ValueError('FIXTURE_COLLISION')
    run(['useradd', '--uid', str(UID), '--no-create-home', '--home-dir', '/tmp',
         '--shell', '/bin/sh', '--no-log-init', USER])
    fd = os.open(RULE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o440)
    with os.fdopen(fd, 'w') as f:
        f.write(USER + ' ALL=(root) NOPASSWD: ALL\n')
    run(['visudo', '-c', '-f', RULE])
    return {'schema': 'ruby-p1-runtime-fixture-r11', 'user': USER, 'uid': UID,
            'sudo_rule_created': True, 'scope': 'disposable_target_only'}


def main():
    mode = sys.argv[1] if len(sys.argv) == 2 else ''
    if mode not in ('baseline', 'fixture') or os.environ.get('RUBY_P1_TARGET_FIXTURE') != '1':
        print('{"status":"REFUSED"}')
        return 3
    try:
        print(json.dumps(baseline() if mode == 'baseline' else fixture(), sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({'status': 'INCOMPLETE', 'stage': mode}))
        return 3


if __name__ == '__main__':
    sys.exit(main())
