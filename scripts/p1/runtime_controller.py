"""Run the fixed Ansible playbook, retaining only the private callback's schema."""
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

from runtime_protocol import stderr_diagnostics

COLLECTION_ROOT = '/home/circleci/.local/lib/python3.14/site-packages/ansible_collections'


def main():
    report = {'schema': 'ruby-p1-runtime-controller-r11', 'status': 'INCOMPLETE',
              'stage': 'preflight'}
    checkpoint = 'controller_identity'
    try:
        if (len(sys.argv) != 2 or not re.fullmatch(r'ruby-p1-[0-9a-f]{32}-runtime-target', sys.argv[1])
                or os.getuid() != 1000 or platform.python_version() != '3.14.10'
                or importlib.metadata.version('ansible-core') != '2.21.6'):
            raise ValueError('CONTROLLER_BASELINE')
        checkpoint = 'collection_manifest'
        manifest = json.loads((Path(COLLECTION_ROOT) / 'community/docker/MANIFEST.json').read_text())
        if manifest['collection_info']['version'] != '5.4.0':
            raise ValueError('COLLECTION_BASELINE')
        # ANSIBLE_LOCAL_TEMP must already be set by the container launcher:
        # importing constants resolves DEFAULT_LOCAL_TMP and creates its directory.
        checkpoint = 'constants_import'
        from ansible import constants as constants
        checkpoint = 'collection_settings'
        paths = constants.COLLECTIONS_PATHS
        scan = constants.COLLECTIONS_SCAN_SYS_PATH
        if (not isinstance(paths, (list, tuple)) or not paths or type(scan) is not bool
                or any(not isinstance(p, str) or not os.path.isabs(p)
                       or os.pathsep in p or any(ord(c) < 32 for c in p) for p in paths)):
            raise ValueError('SEARCH_PATH')
        checkpoint = 'environment_copy'
        env = os.environ.copy()
        env.update(ANSIBLE_HOME='/tmp/ruby-p1-runtime-home',
                   ANSIBLE_COLLECTIONS_PATH=os.pathsep.join(paths),
                   ANSIBLE_COLLECTIONS_SCAN_SYS_PATH='true' if scan else 'false',
                   ANSIBLE_LOCAL_TEMP='/tmp/ruby-p1-runtime-local',
                   ANSIBLE_NOCOLOR='1', NO_COLOR='1', PYTHONDONTWRITEBYTECODE='1',
                   ANSIBLE_STDOUT_CALLBACK='runtime_callback',
                   ANSIBLE_CALLBACK_PLUGINS='/p1/callback_plugins', ANSIBLE_CALLBACKS_ENABLED='',
                   ANSIBLE_LOG_PATH='/dev/null', ANSIBLE_FORCE_COLOR='0')
        # Use a known private config and inventory; do not load the checkout's cfg.
        checkpoint = 'workspace_create'
        with tempfile.TemporaryDirectory(prefix='ruby-p1-runtime-', dir='/tmp') as tmp:
            tmp = Path(tmp)
            checkpoint = 'config_write'
            cfg = tmp / 'ansible.cfg'
            cfg.write_text('[defaults]\nretry_files_enabled=False\nforks=1\n'
                           'timeout=20\n[connection]\npipelining=True\n')
            env['ANSIBLE_CONFIG'] = str(cfg)
            inventory = {'all': {'hosts': {'target': {
                'ansible_host': sys.argv[1], 'ansible_user': 'root',
                'ansible_connection': 'community.docker.docker_api'}}}}
            checkpoint = 'inventory_write'
            inv = tmp / 'inventory.json'
            inv.write_text(json.dumps(inventory))
            checkpoint = 'playbook_lookup'
            exe = shutil.which('ansible-playbook')
            if not exe:
                raise ValueError('PLAYBOOK_UNAVAILABLE')
            report['stage'] = 'ansible_playbook'
            checkpoint = 'playbook_execute'
            p = subprocess.run([exe, '-i', str(inv), '/p1/runtime_smoke.yml'],
                               env=env, cwd=tmp, capture_output=True, text=True,
                               timeout=180, check=False)
            checkpoint = 'playbook_result'
            report['command'] = {'returncode': p.returncode,
                                 'stdout_bytes': len(p.stdout.encode()),
                                 'stderr_bytes': len(p.stderr.encode())}
            if p.returncode or p.stderr or len(p.stdout.encode()) > 32768:
                report['diagnostics'] = stderr_diagnostics(p.stderr)
                raise ValueError('PLAYBOOK_FAILED_OR_WARNING')
            checkpoint = 'callback_decode'
            value = json.loads(p.stdout)
            checkpoint = 'callback_schema'
            if (set(value) != {'schema', 'status', 'measurements'}
                    or value['schema'] != 'ruby-p1-ansible-runtime-r11'
                    or value['status'] != 'PASSED'):
                raise ValueError('CALLBACK_INCOMPLETE')
            # The host repeats schema validation before persisting these measurements.
            report['ansible'] = value
            checkpoint = 'workspace_cleanup'
        report.update(status='PASSED', stage='finished')
    except Exception:
        report.update(status='INCOMPLETE', reason='RUNTIME_UNCONFIRMED',
                      checkpoint=checkpoint)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'PASSED' else 3


if __name__ == '__main__':
    sys.exit(main())
