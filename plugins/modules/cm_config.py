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
module: cm_config
short_description: Manage the configuration of Cloudera Manager
description:
  - Manage Cloudera Manager configuration settings.
author:
  - "Webster Mudge (@wmudge)"
version_added: "4.4.0"
requirements:
  - cm_client
options:
  parameters:
    description:
      - The Cloudera Manager configuration to set.
      - To unset a parameter, use C(None) as the value.
    type: dict
    required: yes
    aliases:
      - params
extends_documentation_fragment:
  - ansible.builtin.action_common_attributes
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - cloudera.cluster.purge
  - cloudera.cluster.message
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  platform:
    platforms: all
"""

EXAMPLES = r"""
- name: Update several Cloudera Manager parameters
  cloudera.cluster.cm_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    parameters:
      frontend_url: "schema://host:port"
      custom_header_color: "PURPLE"

- name: Reset or remove a Cloudera Manager parameter
  cloudera.cluster.cm_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    parameters:
      custom_header_color: None
"""

RETURN = r"""
config:
  description:
    - List of Cloudera Manager configurations.
    - Returns the C(summary) view of the resulting configuration.
  type: list
  elements: dict
  returned: always
  contains:
    name:
      description:
        - The canonical name that identifies this configuration parameter.
      type: str
      returned: when supported
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
        - Whether this configuration is sensitive, i.e. contains information such as passwords, which might affect how the value of this configuration might be shared by the caller.
      type: bool
      returned: when supported
    validate_state:
      description:
        - State of the configuration parameter after validation.
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

import cm_client

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerMutableModule,
    resolve_parameter_changeset,
)


class ClouderaManagerConfig(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClouderaManagerConfig, self).__init__(module)

        # Set the parameters
        self.params = self.get_param("parameters")
        self.purge = self.get_param("purge")

        # Initialize the return value
        self.changed = False
        self.diff = {}
        self.config = []

        # Execute the logic
        self.process()

    @ClouderaManagerMutableModule.handle_process
    def process(self):
        refresh = True
        existing = self.get_cm_config()

        current = {r.name: r.value for r in existing}
        incoming = {k.upper(): v for k, v in self.params.items()}

        change_set = resolve_parameter_changeset(current, incoming, self.purge)

        if change_set:
            self.changed = True

            if self.module._diff:
                self.diff = dict(
                    before={k: current[k] for k in change_set.keys()},
                    after=change_set,
                )

            if not self.module.check_mode:
                body = cm_client.ApiConfigList(
                    items=[
                        cm_client.ApiConfig(name=k, value=v)
                        for k, v in change_set.items()
                    ]
                )
                # Return 'summary'
                refresh = False
                self.config = [
                    p.to_dict()
                    for p in cm_client.ClouderaManagerResourceApi(self.api_client)
                    .update_config(message=self.message, body=body)
                    .items
                ]

        if refresh:
            # Return 'summary'
            self.config = [p.to_dict() for p in self.get_cm_config()]


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            parameters=dict(type=dict, required=True, aliases=["params"]),
            purge=dict(type="bool", default=False),
        ),
        supports_check_mode=True,
    )

    result = ClouderaManagerConfig(module)

    output = dict(
        changed=result.changed,
        config=result.config,
    )

    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
