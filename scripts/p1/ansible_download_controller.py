"""Run actual uri/stat/assert tasks; emit only the bounded callback report."""
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent


def validate_variables(value):
    if (type(value) is not dict or set(value) != {'p1_url', 'p1_destination', 'p1_sha256', 'p1_ca'}
            or any(type(x) is not str for x in value.values())
            or not re.fullmatch(r'https://(?:localhost|127\.0\.0\.1):[0-9]{1,5}/source', value['p1_url'])
            or not re.fullmatch(r'/tmp/ruby-p1-ansible-[a-z0-9_]+/case-(?:[0-9]|1[0-5])/source\.tar\.gz', value['p1_destination'])
            or not re.fullmatch(r'[0-9a-f]{64}', value['p1_sha256'])
            or value['p1_ca'] not in ('', str(Path(value['p1_destination']).parents[1] / 'cert.pem'))):
        raise ValueError('VARIABLES')


def execute(variables, target=None):
    validate_variables(variables)
    if importlib.metadata.version('ansible-core') != '2.21.6':
        raise ValueError('CORE_VERSION')
    if target is not None:
        if (not re.fullmatch('ruby-p1-[0-9a-f]{32}-fetch-target', target)
                or platform.python_version() != '3.14.10' or os.getuid() != 1000):
            raise ValueError('CONTROLLER_BASELINE')
        manifest = Path('/home/circleci/.local/lib/python3.14/site-packages/ansible_collections/community/docker/MANIFEST.json')
        if json.loads(manifest.read_text())['collection_info']['version'] != '5.4.0':
            raise ValueError('COLLECTION_BASELINE')
    # Keep the installed collection search paths; isolate config/home/callbacks.
    with tempfile.TemporaryDirectory(prefix='ruby-p1-fetch-controller-') as directory:
        root = Path(directory)
        callbacks = root / 'callbacks'
        callbacks.mkdir()
        shutil.copyfile(ROOT / 'ansible_download_callback.py', callbacks / 'ansible_download_callback.py')
        cfg = root / 'ansible.cfg'
        cfg.write_text('[defaults]\nretry_files_enabled=False\nforks=1\ntimeout=15\n[connection]\npipelining=True\n')
        host = {'ansible_connection': 'community.docker.docker_api' if target else 'local',
                'ansible_host': target or 'localhost', 'ansible_user': '65534' if target else str(os.geteuid()),
                'ansible_python_interpreter': '/usr/bin/python3' if target else sys.executable}
        (root / 'inventory.json').write_text(json.dumps({'all': {'hosts': {'target': host}}}))
        (root / 'vars.json').write_text(json.dumps(variables))
        env = {k: v for k, v in os.environ.items() if not k.startswith('ANSIBLE_')}
        env.update(ANSIBLE_CONFIG=str(cfg), ANSIBLE_HOME=str(root / 'home'),
                   ANSIBLE_LOCAL_TEMP=str(root / 'local'), ANSIBLE_STDOUT_CALLBACK='ansible_download_callback',
                   ANSIBLE_CALLBACK_PLUGINS=str(callbacks), ANSIBLE_LOG_PATH='/dev/null',
                   ANSIBLE_NOCOLOR='1', ANSIBLE_FORCE_COLOR='0', PYTHONDONTWRITEBYTECODE='1')
        # ANSIBLE_HOME changes the default path. Preserve the installed collection
        # location used by the fixed controller without adding user-supplied paths.
        if target:
            env['ANSIBLE_COLLECTIONS_PATH'] = '/home/circleci/.local/lib/python3.14/site-packages/ansible_collections'
        executable = str(Path(sys.executable).parent / 'ansible-playbook')
        if not Path(executable).is_file():
            executable = shutil.which('ansible-playbook')
        if not executable:
            raise ValueError('PLAYBOOK_UNAVAILABLE')
        p = subprocess.run([executable, '-i', str(root / 'inventory.json'),
                            str(ROOT / 'ansible_download.yml'), '-e', '@' + str(root / 'vars.json')],
                           cwd=root, env=env, capture_output=True, text=True, timeout=25, check=False)
        if p.returncode or p.stderr or len(p.stdout.encode()) > 8192:
            raise ValueError('PLAYBOOK_FAILED_OR_WARNING')
        value = json.loads(p.stdout)
        if (type(value) is not dict or set(value) != {'schema', 'status', 'publication', 'events'}
                or value['schema'] != 'ruby-p1-ansible-acquisition-events-r49'
                or value['status'] != 'RECORDED'):
            raise ValueError('CALLBACK_INCOMPLETE')
        return value


if __name__ == '__main__':
    try:
        request = json.load(sys.stdin)
        if set(request) != {'variables', 'target'}:
            raise ValueError('REQUEST')
        result = execute(request['variables'], request['target'])
        print(json.dumps(result, sort_keys=True))
    except Exception:
        print(json.dumps({'status': 'INCOMPLETE', 'reason': 'ANSIBLE_EXECUTION_UNCONFIRMED'}))
        raise SystemExit(3)
