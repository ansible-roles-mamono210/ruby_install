"""Private callback: retain only enumerated measurements, never raw Ansible results."""
import json
from ansible.plugins.callback import CallbackBase

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runtime_protocol import FACTS, TASKS, selected

PUBLICATION = 'P1 publish bounded measurements'


def measurements(payload):
    """Accept only the deliberate publication, not a raw Ansible task result."""
    if (type(payload) is not dict or set(payload) != {'schema', 'facts', 'commands'}
            or payload['schema'] != 'ruby-p1-runtime-publication-r16'
            or type(payload['facts']) is not dict or set(payload['facts']) != set(FACTS)
            or type(payload['commands']) is not dict or set(payload['commands']) != set(TASKS[2:])):
        raise ValueError('PUBLICATION')
    values = {TASKS[0]: selected(TASKS[0], {'ansible_facts': payload['facts']}),
              TASKS[1]: {'assertion_passed': True}}
    for name in TASKS[2:]:
        row = payload['commands'][name]
        if (type(row) is not dict or set(row) != {'rc', 'stdout', 'stderr_present'}
                or type(row['rc']) is not int or type(row['stdout']) is not str
                or len(row['stdout'].encode('utf-8')) > 32768
                or type(row['stderr_present']) is not bool):
            raise ValueError('COMMAND_FIELDS')
        values[name] = selected(name, {'rc': row['rc'], 'stdout': row['stdout'],
                                       'stderr': row['stderr_present']})
    return values


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'runtime_callback'

    def __init__(self):
        super().__init__()
        self.values = {}
        self.completed = []
        self.failed = False

    def v2_runner_on_ok(self, result):
        if self.failed:
            return
        try:
            # Core 2.21.6 censors result.result for no_log tasks. Do not bypass
            # that boundary: use only event metadata until the final task.
            name = result.task_name
            if (result.host.get_name() != 'target' or result.warnings or result.deprecations
                    or result.is_failed() or result.is_skipped() or result.is_unreachable()):
                raise ValueError('EVENT')
            if len(self.completed) < len(TASKS):
                if name != TASKS[len(self.completed)] or result.task.no_log is not True:
                    raise ValueError('ORDER')
                self.completed.append(name)
                return
            if name != PUBLICATION or self.values or result.task.no_log is not False:
                raise ValueError('ORDER')
            # This task publishes four facts and four fixed probe outputs only.
            # Never emit its invocation, whole result, raw stderr, or warnings.
            self.values = measurements(result.result['msg'])
        except Exception:
            self.failed = True

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self.failed = True

    def v2_runner_on_unreachable(self, result):
        self.failed = True

    def v2_runner_on_skipped(self, result):
        self.failed = True

    def v2_playbook_on_stats(self, stats):
        ok = not self.failed and tuple(self.completed) == TASKS and tuple(self.values) == TASKS
        summary = {'schema': 'ruby-p1-ansible-runtime-r11',
                   'status': 'PASSED' if ok else 'INCOMPLETE',
                   'measurements': self.values if ok else {}}
        self._display.display(json.dumps(summary, sort_keys=True))
