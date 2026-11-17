"""Publish only deliberate bounded fields; never raw task results."""
import json
from ansible.plugins.callback import CallbackBase

FIELDS = {'schema', 'failure_stage', 'http_status', 'uri_failed',
          'tls_verification_failed', 'stat_ran', 'checksum_matches', 'gate_reached'}
TASKS = {'P1 uri', 'P1 stat', 'P1 checksum', 'P1 gate witness',
         'P1 remember failure stage', 'P1 publish acquisition result'}


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'ansible_download_callback'

    def __init__(self):
        super().__init__()
        self.publication = None
        self.events = []
        self.invalid = False

    def record(self, result, state):
        try:
            name = result.task_name
            if (result.host.get_name() != 'target' or name not in TASKS
                    or result.warnings or result.deprecations):
                raise ValueError('EVENT')
            self.events.append({'task': name, 'state': state})
            if name == 'P1 publish acquisition result':
                value = result.result['msg']
                if (state != 'ok' or result.task.no_log is not False
                        or self.publication is not None or type(value) is not dict
                        or set(value) != FIELDS
                        or value['schema'] != 'ruby-p1-ansible-acquisition-case-r49'
                        or value['failure_stage'] not in {'none', 'P1 uri', 'P1 checksum'}
                        or type(value['http_status']) is not int
                        or value['http_status'] not in {-1, 200, 300, 301, 302, 303, 307, 308}
                        or any(type(value[k]) is not bool for k in FIELDS - {'schema', 'failure_stage', 'http_status'})):
                    raise ValueError('PUBLICATION')
                self.publication = value
            elif result.task.no_log is not True:
                raise ValueError('PRIVATE_TASK')
        except Exception:
            self.invalid = True

    def v2_runner_on_ok(self, result):
        self.record(result, 'ok')

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self.record(result, 'failed')
        if ignore_errors:
            self.invalid = True

    def v2_runner_on_unreachable(self, result):
        self.invalid = True

    def v2_runner_on_skipped(self, result):
        self.invalid = True

    def v2_playbook_on_stats(self, stats):
        ok = (not self.invalid and self.publication is not None
              and not any(stats.failures.values()) and not any(stats.dark.values()))
        print(json.dumps({'schema': 'ruby-p1-ansible-acquisition-events-r49',
                          'status': 'RECORDED' if ok else 'INCOMPLETE',
                          'publication': self.publication if ok else None,
                          'events': self.events if ok else []}, sort_keys=True))
