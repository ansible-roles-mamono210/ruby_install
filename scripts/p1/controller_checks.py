"""Offline controller checks; injected before container_probe.py, no daemon calls."""
import importlib.metadata as md
import json
import os
import re
import subprocess
import sys
import time

CHECK_SCHEMA = 'ruby-p1-controller-checks-r5'
EXPECTED_ENTRY = 'molecule_plugins.docker.driver:Docker'
REQUIRED = {'molecule': '>=25.1.0', 'docker': '>=4.3.1', 'requests': '', 'selinux': ''}


def normalized(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def dependency_metadata():
    """Evaluate installed METADATA with docker enabled; never emit raw metadata."""
    out = {'status': 'INCOMPLETE', 'requirements': [], 'versions': {},
           'docker_entry_count': 0, 'entry_owner_expected': False,
           'entry_value_expected': False, 'legacy_distribution_count': 0,
           'plugin_distribution_count': 0}
    try:
        from packaging.markers import default_environment
        from packaging.requirements import Requirement
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version
        env = default_environment()
        env['extra'] = 'docker'
        plugins = md.distribution('molecule-plugins')
        active = []
        for raw in plugins.requires or []:
            req = Requirement(raw)
            if req.marker is not None and not req.marker.evaluate(env):
                continue
            name = normalized(req.name)
            if name not in REQUIRED or req.url is not None:
                out['error_code'] = 'UNEXPECTED_OR_URL_REQUIREMENT'
                return out
            active.append(name)
            try:
                value = md.version(req.name)
            except md.PackageNotFoundError:
                value = None
            valid = value is not None and bool(re.fullmatch(r'[0-9][0-9A-Za-z.!+_-]{0,79}', value))
            out['versions'][name] = value if valid else None
            satisfied = bool(valid and Version(value) in req.specifier
                             and Version(value) in SpecifierSet(REQUIRED[name]))
            out['requirements'].append({'name': name, 'present': value is not None,
                                        'satisfied': satisfied,
                                        'declared_constraint_matches': str(req.specifier) == REQUIRED[name]})
        out['active_requirement_set_expected'] = sorted(active) == sorted(REQUIRED)
        entries = []
        for dist in md.distributions():
            name = normalized(dist.metadata.get('Name') or '')
            out['legacy_distribution_count'] += name == 'molecule-docker'
            out['plugin_distribution_count'] += name == 'molecule-plugins'
            entries += [(name, ep.value) for ep in dist.entry_points
                        if ep.group == 'molecule.driver' and ep.name == 'docker']
        out['docker_entry_count'] = len(entries)
        out['entry_owner_expected'] = len(entries) == 1 and entries[0][0] == 'molecule-plugins'
        out['entry_value_expected'] = len(entries) == 1 and entries[0][1] == EXPECTED_ENTRY
        matched = (out['active_requirement_set_expected']
                   and all(r['satisfied'] and r['declared_constraint_matches'] for r in out['requirements'])
                   and out['entry_owner_expected'] and out['entry_value_expected']
                   and out['legacy_distribution_count'] == 0 and out['plugin_distribution_count'] == 1)
        out['status'] = 'MATCH' if matched else 'MISMATCH'
    except Exception:
        # Errors can contain local paths, URL credentials or arbitrary METADATA.
        out['error_code'] = 'METADATA_UNAVAILABLE_OR_INVALID'
    return out


def check_command(args):
    """Capture privately; only return output to fixed parsers, never to evidence."""
    started = time.monotonic()
    result = {'state': 'OS_ERROR', 'returncode': None, 'errno': None,
              'stdout_bytes': 0, 'stderr_bytes': 0}
    stdout = stderr = b''
    try:
        process = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                                 timeout=15, env=os.environ.copy(), check=False)
        stdout, stderr = process.stdout, process.stderr
        result.update(state='EXITED', returncode=process.returncode)
    except subprocess.TimeoutExpired as exc:
        result['state'] = 'TIMEOUT'
        stdout, stderr = exc.stdout or b'', exc.stderr or b''
    except OSError as exc:
        result['errno'] = exc.errno
    result.update(stdout_bytes=len(stdout), stderr_bytes=len(stderr),
                  elapsed_ms=round((time.monotonic() - started) * 1000))
    if max(len(stdout), len(stderr)) > 1024 * 1024:
        result['state'] = 'OUTPUT_TOO_LARGE'
    # Imported helpers are defined later by the inventory source in the same interpreter.
    result.update(warning_facts(stderr))
    usable = result['state'] == 'EXITED' and result['returncode'] == 0
    return result, stdout if usable else b''


def controller_checks():
    out = {'schema': CHECK_SCHEMA, 'metadata': dependency_metadata(), 'commands': {}}
    commands = out['commands']
    commands['pip_check'], _ = check_command([sys.executable, '-m', 'pip', 'check'])
    for module in ('docker', 'requests', 'selinux'):
        commands['import_' + module], _ = check_command(
            [sys.executable, '-c', 'import importlib; importlib.import_module(' + repr(module) + ')'])
    metadata = out['metadata']
    if (metadata['status'] != 'MATCH'):
        # Duplicated or unexpected entry points are never loaded by this probe.
        out['driver_checks'] = 'SKIPPED_METADATA_NOT_MATCHED'
        return out
    entry_code = (
        'import importlib.metadata as m; '
        'e=[e for e in m.distribution("molecule-plugins").entry_points '
        'if e.group=="molecule.driver" and e.name=="docker"]; '
        'assert len(e)==1 and e[0].value=="molecule_plugins.docker.driver:Docker"; '
        'c=e[0].load(); from molecule.api import Driver; '
        'assert isinstance(c,type) and issubclass(c,Driver); '
        'assert c.__module__=="molecule_plugins.docker.driver" and c.__name__=="Docker"'
    )
    commands['entry_load'], _ = check_command([sys.executable, '-c', entry_code])
    commands['molecule_drivers'], data = check_command(
        [sys.executable, '-m', 'molecule', 'drivers', '--format', 'simple'])
    # A fixed token is enough; do not persist arbitrary driver names or CLI output.
    commands['molecule_drivers']['docker_exact_lines'] = data.splitlines().count(b'docker')
    out['driver_checks'] = 'EXECUTED'
    return out
