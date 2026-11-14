"""Strict allowlisted runtime evidence protocol, shared by host and callback."""
import json

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

