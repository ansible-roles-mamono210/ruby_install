#!/usr/bin/python
"""Ansible entry for building a permitted new installation."""
from __future__ import absolute_import, division, print_function

DOCUMENTATION = r'''
---
module: ruby_install_build
short_description: Build and verify a new managed Ruby installation
description:
  - Install a verified Ruby source in a dedicated prefix and publish a completed record.
options:
  version:
    description: Stable Ruby 3.4 or 4.0 patch version.
    type: str
    required: true
  prefix:
    description: Dedicated absolute installation path.
    type: path
    required: true
  workspace:
    description: Build directory parent.
    type: path
    required: true
  work:
    description: Private directory created by the calling Role.
    type: path
    required: true
  work_dev:
    description: Device of the private directory created for this run.
    type: int
    required: true
  work_inode:
    description: Inode of the private directory created for this run.
    type: int
    required: true
  digest:
    description: Resolved SHA-256 of the source file.
    type: str
    required: true
  documentation:
    description: Build standard ri documentation.
    type: bool
    required: true
  jobs:
    description: Positive number of parallel make jobs.
    type: int
    required: true
  keep:
    description: Retain the private directory after success.
    type: bool
    required: true
author:
  - mamono210
'''
EXAMPLES = r'''
# The Role calls this internal module after creating a private directory,
# verifying the dependency transaction and checking the downloaded SHA-256.
'''
RETURN = r'''
workspace:
  description: Private directory used by this installation.
  returned: always
  type: str
'''
import os
import re
import tarfile
import zlib

from ansible.module_utils.basic import AnsibleModule


def main():
    types = {"version": "str", "prefix": "path", "workspace": "path", "work": "path",
             "work_dev": "int", "work_inode": "int", "digest": "str", "documentation": "bool",
             "jobs": "int", "keep": "bool"}
    module = AnsibleModule(argument_spec={k: {"type": v, "required": True} for k, v in types.items()})
    from ansible.module_utils.ruby_install_preflight.build import install
    from ansible.module_utils.ruby_install_preflight.state import Stop
    p = module.params
    if (os.geteuid() != 0 or not re.fullmatch(r"(?:3\.4|4\.0)\.(?:0|[1-9][0-9]*)", p["version"])
            or not re.fullmatch(r"[0-9a-f]{64}", p["digest"]) or p["jobs"] < 1):
        module.fail_json(msg="INVALID_INPUT: a privileged build with validated version, checksum and jobs is required")
    progress = {"stage": "workspace"}
    try:
        install(p, progress)
    except (Stop, OSError, ValueError, EOFError, OverflowError, tarfile.TarError, zlib.error) as exc:
        message = str(exc) if isinstance(exc, Stop) else type(exc).__name__
        module.fail_json(changed=True, msg=message, workspace=p["work"], **progress)
    module.exit_json(changed=True, workspace=p["work"])


if __name__ == "__main__":
    main()
