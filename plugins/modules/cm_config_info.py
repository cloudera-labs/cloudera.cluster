#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2023 Cloudera, Inc. All Rights Reserved.
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
module: cm_config_info
short_description: Retrieve the Cloudera Manager configuration
description:
  - Retrieve the Cloudera Manager configuration settings.
  - The module supports C(check_mode).
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
options:
  view:
    description:
      - The view to materialize, either C(summary) or C(full).
    type: str
    default: summary
    choices:
        - summary
        - full
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
"""

EXAMPLES = r"""
- name: Retrieve the summary (default) settings
  cloudera.cluster.cm_config_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
  register: summary

- name: Retrieve the full settings
  cloudera.cluster.cm_config_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    view: full
  register: full
"""

RETURN = r"""
config:
  description:
    - List of Cloudera Manager Server configurations.
  type: list
  elements: dict
  returned: always
  contains:
    name:
      description:
        - The canonical name that identifies this configuration parameter.
      type: str
      returned: always
    value:
      description:
        - The user-defined value.
        - When absent, the default value (if any) will be used.
        - Can also be absent, when enumerating allowed configs.
      type: str
      returned: when supported
    required:
      description:
        - Whether this configuration is required for the object.
        - If any required configuration is not set, operations on the object may not work.
        - Requires I(full) view.
      type: bool
      returned: when supported
    default:
      description:
        - The default value.
        - Requires I(full) view.
      type: str
      returned: when supported
    display_name:
      description:
        - A user-friendly name of the parameters, as would have been shown in the web UI.
        - Requires I(full) view.
      type: str
      returned: when supported
    description:
      description:
        - A textual description of the parameter.
        - Requires I(full) view.
      type: str
      returned: when supported
    related_name:
      description:
        - If applicable, contains the related configuration variable used by the source project.
        - Requires I(full) view.
      type: str
      returned: when supported
    sensitive:
      description:
        - Whether this configuration is sensitive, i.e. contains information such as passwords.
        - This parameter might affect how the value of this configuration might be shared by the caller.
      type: bool
      returned: when supported
    validate_state:
      description:
        - State of the configuration parameter after validation.
        - For example, C(OK), C(WARNING), and C(ERROR).
        - Requires I(full) view.
      type: str
      returned: when supported
    validation_message:
      description:
        - A message explaining the parameter's validation state.
        - Requires I(full) view.
      type: str
      returned: when supported
    validation_warnings_suppressed:
      description:
        - Whether validation warnings associated with this parameter are suppressed.
        - In general, suppressed validation warnings are hidden in the Cloudera Manager UI.
        - Configurations that do not produce warnings will not contain this field.
        - Requires I(full) view.
      type: bool
      returned: when supported
"""

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)


class ClouderaManagerConfigInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaManagerConfigInfo, self).__init__(module)

        # Set the parameters
        self.view = self.get_param("view")

        # Initialize the return value
        self.config = []

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        self.config = [r.to_dict() for r in self.get_cm_config(self.view)]


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(view=dict(default="summary", choices=["summary", "full"])),
        supports_check_mode=True,
    )

    result = ClouderaManagerConfigInfo(module)

    output = dict(
        changed=False,
        config=result.config,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
