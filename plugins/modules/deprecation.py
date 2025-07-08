#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2025 Cloudera, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

DOCUMENTATION = r"""
module: deprecation
short_description: Display a deprecation warning
description:
  - Displays a standard Ansible deprecation warning
author:
  - "Webster Mudge (@wmudge)"
version_added: "5.0.0"
options:
  msg:
    description:
      - The deprecation warning message.
    type: str
    required: true
  version:
    description:
      - Version details for the warning message.
    type: str
    required: false
"""

EXAMPLES = r"""
- name: Display a deprecation warning
  cloudera.cluster.deprecation:
    msg: A custom warning

- name: Display the deprecation warning with version details
  cloudera.cluster.deprecation:
    msg: A custom warning with version info
    version: "5.0.0"
"""

RETURN = r""""""

from ansible.module_utils.basic import AnsibleModule


if __name__ == "__main__":
    module = AnsibleModule(
        argument_spec=dict(
            msg=dict(required="True"),
            version=dict(),
        ),
    )

    module.deprecate(module.params.get("msg"), module.params.get("version", None))
    module.exit_json()
