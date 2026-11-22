#!/usr/bin/python
"""Ansible entry for opt-in links from an already verified Ruby installation."""
from __future__ import absolute_import, division, print_function

DOCUMENTATION = r'''
---
module: ruby_install_links
short_description: Publish the selected Ruby commands in /usr/local/bin
description:
  - Recheck the recorded installation, sources and destinations before publishing.
  - Check mode predicts the missing links for an existing installation.
options:
  version:
    description: Requested Ruby patch version.
    type: str
    required: true
  prefix:
    description: Dedicated installation prefix.
    type: path
    required: true
  workspace:
    description: Configured build workspace parent.
    type: path
    required: true
  digest:
    description: Expected source SHA-256.
    type: str
    required: true
  documentation:
    description: Expected documentation setting in the installation record.
    type: bool
    required: true
  link_commands:
    description: Ordered list of selected command names.
    type: list
    elements: str
    required: true
author:
  - mamono210
'''
EXAMPLES = r'''
# Invoked by the Role after the new installation or on a healthy recorded rerun.
'''
RETURN = r'''
created:
  description: Links created by this task.
  returned: success or failure during creation
  type: list
  elements: str
not_created:
  description: Planned links still outstanding after a creation failure.
  returned: failure during creation
  type: list
  elements: str
would_create:
  description: Missing links observed during check mode.
  returned: check mode
  type: list
  elements: str
'''
import os

from ansible.module_utils.basic import AnsibleModule


def main():
    types = {"version": "str", "prefix": "path", "workspace": "path", "digest": "str", "documentation": "bool"}
    options = {key: {"type": value, "required": True} for key, value in types.items()}
    options["link_commands"] = {"type": "list", "elements": "str", "required": True}
    module = AnsibleModule(argument_spec=options, supports_check_mode=True)
    from ansible.module_utils.ruby_install_preflight.health import health_check
    from ansible.module_utils.ruby_install_preflight.links import LinkCreationError, create_links
    from ansible.module_utils.ruby_install_preflight.state import Stop, inspect_with_links

    if os.geteuid() != 0 or not module.params["link_commands"]:
        module.fail_json(msg="INVALID_INPUT: publication requires root and a nonempty command selection")
    try:
        status, plan = inspect_with_links(module.params, health_check)
        if status != "installed_healthy":
            raise Stop("INSTALLATION_INCOMPLETE: publication requires a healthy recorded Ruby")
        if module.check_mode:
            module.exit_json(changed=bool(plan.missing), created=[], would_create=list(plan.missing))
        created = create_links(plan)
    except LinkCreationError as exc:
        module.fail_json(changed=bool(exc.created), msg=str(exc), created=exc.created, not_created=exc.not_created)
    except Stop as exc:
        module.fail_json(changed=False, msg=str(exc))
    module.exit_json(changed=bool(created), created=created)


if __name__ == "__main__":
    main()
