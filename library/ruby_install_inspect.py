#!/usr/bin/python
"""Ansible adapter for the read-only Ruby installation preflight."""
from __future__ import absolute_import, division, print_function

DOCUMENTATION = r'''
---
module: ruby_install_inspect
short_description: Inspect the managed Ruby prefix
description:
  - Examine a CentOS Stream 9 installation candidate or an existing, recorded Ruby.
  - The calling Role validates public inputs and resolves the source checksum.
options:
  version:
    description: Full Ruby patch version.
    type: raw
    required: true
  prefix:
    description: Absolute managed installation path.
    type: raw
    required: true
  workspace:
    description: Absolute build workspace parent.
    type: raw
    required: true
  digest:
    description: Resolved lowercase SHA-256 of the requested source.
    type: raw
    required: true
  documentation:
    description: Expected native boolean documentation setting.
    type: raw
    required: true
  link_commands:
    description: Selected public command names. An empty list checks for residual links.
    type: list
    elements: str
    default: []
author:
  - mamono210
'''
EXAMPLES = r'''
- name: Inspect a Ruby 3.4.12 prefix
  ruby_install_inspect:
    version: '3.4.12'
    prefix: /opt/ruby
    workspace: /tmp
    digest: 5e5d85ad93b0adcccbad47733680f4892bd0078e3342437f7babce01c1872479
    documentation: true
'''
RETURN = r'''
state:
  description: Either new_install_allowed or installed_healthy.
  returned: success
  type: str
check_mode:
  description: Effective check mode of this task.
  returned: success
  type: bool
'''
import os
import re

from ansible.module_utils.basic import AnsibleModule


def main():
    fields = ("version", "prefix", "workspace", "digest", "documentation")
    options = {key: {"type": "raw", "required": True} for key in fields}
    options["link_commands"] = {"type": "list", "elements": "str", "default": []}
    module = AnsibleModule(argument_spec=options, supports_check_mode=True)
    from ansible.module_utils.ruby_install_preflight.health import health_check
    from ansible.module_utils.ruby_install_preflight.state import Stop, inspect, overlaps

    p = module.params
    if (type(p["documentation"]) is not bool or any(not isinstance(p[k], str) for k in fields[:-1])
            or not re.fullmatch(r"(?:3\.4|4\.0)\.(?:0|[1-9][0-9]*)", p["version"])
            or not re.fullmatch(r"[0-9a-f]{64}", p["digest"])
            or any(not s.startswith("/") or s.startswith("//") or not s.isprintable() or os.path.normpath(s) != s
                   for s in (p["prefix"], p["workspace"])) or overlaps(p["prefix"], p["workspace"])):
        module.fail_json(msg="INVALID_INPUT: expected normalized Role inputs with native types")
    if os.geteuid() != 0:
        module.fail_json(msg="INSUFFICIENT_PRIVILEGES: target preflight requires effective uid 0")
    try:
        result = inspect(p, health_check)
    except Stop as exc:
        module.fail_json(changed=False, msg=str(exc))
    else:
        module.exit_json(changed=False, state=result, check_mode=module.check_mode)


if __name__ == "__main__":
    main()
