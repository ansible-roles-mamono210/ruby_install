"""Private callback: retain only enumerated measurements, never raw Ansible results."""
import json
from ansible.plugins.callback import CallbackBase

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runtime_protocol import TASKS, selected


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'runtime_callback'

    def __init__(self):
        super().__init__()
        self.values = {}
        self.failed = False

    def v2_runner_on_ok(self, result):
        name = result._task.get_name()
        try:
            if name != TASKS[len(self.values)] or name in self.values:
                raise ValueError('ORDER')
            self.values[name] = selected(name, result._result)
        except Exception:
            self.failed = True

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self.failed = True

    def v2_runner_on_unreachable(self, result):
        self.failed = True

    def v2_runner_on_skipped(self, result):
        self.failed = True

    def v2_playbook_on_stats(self, stats):
        ok = not self.failed and tuple(self.values) == TASKS
        summary = {'schema': 'ruby-p1-ansible-runtime-r11',
                   'status': 'PASSED' if ok else 'INCOMPLETE', 'measurements': self.values}
        self._display.display(json.dumps(summary, sort_keys=True))
