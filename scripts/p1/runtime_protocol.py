"""Strict allowlisted runtime evidence protocol, shared by host and callback."""
import json
import re

DIAGNOSTIC_SCHEMA = 'ruby-p1-stderr-markers-r13'
DIAGNOSTIC_LIMIT = 32768
DIAGNOSTIC_CLASSES = ('EMPTY', 'MARKERS_FOUND', 'UNCLASSIFIED', 'TOO_LARGE',
                      'UNSUPPORTED_CONTROL', 'INVALID_TYPE')
EXCEPTION_LABELS = ('AnsibleError', 'AssertionError', 'AttributeError',
                    'BrokenPipeError', 'ConnectionError', 'ConnectionRefusedError',
                    'EOFError', 'FileExistsError', 'FileNotFoundError', 'ImportError',
                    'KeyError', 'MemoryError', 'ModuleNotFoundError', 'NotImplementedError',
                    'OSError', 'PermissionError', 'RecursionError', 'RuntimeError',
                    'TimeoutError', 'TypeError', 'ValueError')
COMPONENT_PATHS = (
    ('ANSIBLE_CLI', '/ansible/cli/__init__.py'),
    ('ANSIBLE_PLUGIN_LOADER', '/ansible/plugins/loader.py'),
    ('ANSIBLE_TASK_QUEUE', '/ansible/executor/task_queue_manager.py'),
    ('ANSIBLE_RPC_HOST', '/ansible/_internal/_rpc_host.py'),
    ('ANSIBLE_CALLBACK_BASE', '/ansible/plugins/callback/__init__.py'),
    ('PROBE_CALLBACK', '/p1/callback_plugins/runtime_callback.py'),
    ('PROBE_PROTOCOL', '/p1/runtime_protocol.py'),
)
COMPONENT_LABELS = tuple(label for label, _path in COMPONENT_PATHS)
ERRNO_MARKERS = (('EPERM', '[Errno 1]'), ('ENOENT', '[Errno 2]'),
                 ('EACCES', '[Errno 13]'), ('ENOSPC', '[Errno 28]'),
                 ('EROFS', '[Errno 30]'))
ERRNO_LABELS = tuple(label for label, _marker in ERRNO_MARKERS)


def stderr_diagnostics(stderr):
    """Emit only finite labels and booleans; matching text is never returned.

    These are textual clues, not a verified traceback or a root-cause verdict.
    Every nonempty stderr still fails the controller's existing success gate.
    """
    value = {'schema': DIAGNOSTIC_SCHEMA, 'classification': 'EMPTY',
             'traceback_present': False, 'unexpected_exception_banner': False,
             'exception_types': [], 'components': [], 'errno_labels': []}
    if type(stderr) is not str:
        value['classification'] = 'INVALID_TYPE'
        return value
    if len(stderr) > DIAGNOSTIC_LIMIT or len(stderr.encode('utf-8', errors='replace')) > DIAGNOSTIC_LIMIT:
        value['classification'] = 'TOO_LARGE'
        return value
    if not stderr:
        return value
    # Accept only SGR color codes; other terminal controls are not interpreted.
    clean = re.sub(r'\x1b\[[0-9;]*m', '', stderr)
    if any((ord(char) < 32 and char not in '\n\r\t') or 127 <= ord(char) < 160 for char in clean):
        value['classification'] = 'UNSUPPORTED_CONTROL'
        return value
    lines = clean.splitlines()
    value['traceback_present'] = any(line.strip() == 'Traceback (most recent call last):' for line in lines)
    value['unexpected_exception_banner'] = 'Unexpected Exception, this is probably a bug.' in clean
    for label in EXCEPTION_LABELS:
        pattern = r'^\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)*' + label + r'(?=:|$)'
        if any(re.match(pattern, line) for line in lines):
            value['exception_types'].append(label)
    frame_paths = []
    for line in lines:
        match = re.fullmatch(r'\s*File "([^"\r\n]{1,2048})", line [0-9]{1,7}(?:, in [^\r\n]{1,256})?\s*', line)
        if match:
            frame_paths.append(match[1])
    for label, path in COMPONENT_PATHS:
        if any(frame == path if label.startswith('PROBE_') else frame.endswith(path) for frame in frame_paths):
            value['components'].append(label)
    for label, marker in ERRNO_MARKERS:
        if marker in clean:
            value['errno_labels'].append(label)
    if any(value[key] for key in ('traceback_present', 'unexpected_exception_banner',
                                  'exception_types', 'components', 'errno_labels')):
        value['classification'] = 'MARKERS_FOUND'
    else:
        value['classification'] = 'UNCLASSIFIED'
    return value


def validate_diagnostics(value):
    """Validate the controller boundary, rebuilding from approved constants."""
    keys = {'schema', 'classification', 'traceback_present', 'unexpected_exception_banner',
            'exception_types', 'components', 'errno_labels'}
    if (type(value) is not dict or set(value) != keys
            or value['schema'] != DIAGNOSTIC_SCHEMA
            or value['classification'] not in DIAGNOSTIC_CLASSES
            or any(type(value[k]) is not bool for k in ('traceback_present', 'unexpected_exception_banner'))):
        raise ValueError('DIAGNOSTIC_SCHEMA')
    result = {key: value[key] for key in ('schema', 'classification', 'traceback_present', 'unexpected_exception_banner')}
    for key, allowed in (('exception_types', EXCEPTION_LABELS),
                         ('components', COMPONENT_LABELS), ('errno_labels', ERRNO_LABELS)):
        entries = value[key]
        if (type(entries) is not list or len(entries) > len(allowed)
                or any(type(item) is not str or item not in allowed for item in entries)
                or entries != [item for item in allowed if item in entries]):
            raise ValueError('DIAGNOSTIC_LABEL')
        result[key] = [item for item in allowed if item in entries]
    has_markers = any(result[key] for key in ('traceback_present', 'unexpected_exception_banner',
                                             'exception_types', 'components', 'errno_labels'))
    if (result['classification'] == 'MARKERS_FOUND') != bool(has_markers):
        raise ValueError('DIAGNOSTIC_CLASSIFICATION')
    return result

TASKS = ('P1 limited facts', 'P1 validate facts', 'P1 stock baseline',
         'P1 create disposable fixture', 'P1 nonroot identity', 'P1 become identity')
FACTS = ('ansible_distribution', 'ansible_distribution_major_version',
         'ansible_python_version', 'ansible_user_uid')
COMMANDS = ('ruby', 'gem', 'bundle', 'bundler', 'irb', 'erb', 'rdoc', 'ri', 'rake')


def path_result(value):
    if set(value) != {'path', 'uid', 'euid', 'commands'}:
        raise ValueError('FIELDS')
    if (not isinstance(value['path'], str) or not 0 < len(value['path']) <= 2048
            or any(ord(c) < 32 for c in value['path'])
            or type(value['uid']) is not int or value['uid'] != 0
            or type(value['euid']) is not int or value['euid'] != 0
            or set(value['commands']) != set(COMMANDS)):
        raise ValueError('PATH')
    for p in value['commands'].values():
        if p is not None and (not isinstance(p, str) or not p.startswith('/')
                              or len(p) > 2048 or any(ord(c) < 32 for c in p)):
            raise ValueError('COMMAND_PATH')
    return value


def selected(name, result):
    if result.get('warnings') or result.get('deprecations'):
        raise ValueError('WARNING')
    if name == TASKS[0]:
        f = result['ansible_facts']
        v = {k: f[k] for k in FACTS}
        expected = dict(zip(FACTS, ('CentOS', '9', '3.9.19', 0)))
        if v != expected or type(v['ansible_user_uid']) is not int:
            raise ValueError('FACTS')
        return v
    if name == 'P1 validate facts':
        if result.get('failed'):
            raise ValueError('ASSERT')
        return {'assertion_passed': True}
    if type(result.get('rc')) is not int or result['rc'] != 0 or result.get('stderr'):
        raise ValueError('COMMAND')
    if name in TASKS[4:]:
        value = result['stdout'].strip()
        if value != ('29999' if name == TASKS[4] else '0'):
            raise ValueError('IDENTITY')
        return {'euid': int(value)}
    value = json.loads(result['stdout'])
    if name == TASKS[3]:
        expected = {'schema': 'ruby-p1-runtime-fixture-r11', 'user': 'ruby_p1_probe',
                    'uid': 29999, 'sudo_rule_created': True, 'scope': 'disposable_target_only'}
        if value != expected or type(value['uid']) is not int or value['sudo_rule_created'] is not True:
            raise ValueError('FIXTURE')
        return value
    if (set(value) != {'schema', 'direct', 'sudo_root', 'mounts', 'tools', 'scope'}
            or value['schema'] != 'ruby-p1-runtime-baseline-r11'
            or value['scope'] != 'stock_image_docker_exec_root_before_fixture'):
        raise ValueError('BASELINE')
    path_result(value['direct']); path_result(value['sudo_root'])
    if set(value['mounts']) != {'/', '/tmp'}:
        raise ValueError('MOUNTS')
    for row in value['mounts'].values():
        if set(row) != {'ro', 'noexec', 'nosuid', 'nodev'} or any(type(v) is not bool for v in row.values()):
            raise ValueError('MOUNTS')
    if value['tools'] != {'sudo': True, 'visudo': True, 'useradd': True} or any(type(v) is not bool for v in value['tools'].values()):
        raise ValueError('TOOLS')
    return value


def validate_report(report):
    if (set(report) != {'schema', 'status', 'stage', 'command', 'ansible'}
            or report['schema'] != 'ruby-p1-runtime-controller-r11'
            or report['status'] != 'PASSED' or report['stage'] != 'finished'):
        raise ValueError('CONTROLLER_REPORT')
    c = report['command']
    if (set(c) != {'returncode', 'stdout_bytes', 'stderr_bytes'}
            or any(type(v) is not int for v in c.values())
            or c['returncode'] != 0 or c['stderr_bytes'] != 0
            or not 0 < c['stdout_bytes'] <= 32768):
        raise ValueError('COMMAND_STATUS')
    a = report['ansible']
    if (set(a) != {'schema', 'status', 'measurements'}
            or a['schema'] != 'ruby-p1-ansible-runtime-r11' or a['status'] != 'PASSED'
            or set(a['measurements']) != set(TASKS)):
        raise ValueError('MEASUREMENTS')
    for name, value in a['measurements'].items():
        if name == TASKS[0]:
            if set(value) != set(FACTS):
                raise ValueError('FACT_KEYS')
            selected(name, {'ansible_facts': value})
        elif name == TASKS[1]:
            if value != {'assertion_passed': True} or value['assertion_passed'] is not True:
                raise ValueError('ASSERTION')
        elif name in TASKS[4:]:
            if set(value) != {'euid'} or type(value['euid']) is not int:
                raise ValueError('UID')
            selected(name, {'rc': 0, 'stdout': str(value['euid'])})
        else:
            selected(name, {'rc': 0, 'stdout': json.dumps(value)})
    return report

