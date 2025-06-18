#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2024 Cloudera, Inc. All Rights Reserved.
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
module: cm_service_role_config
short_description: Manage a service role configuration in cluster
description:
  - Manage a service role configuration (role-specific) in a cluster.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm-client
options:
  name:
    description:
      - A Cloudera Manager Service role name to manage.
      - One of C(name) or C(type) is required.
    type: str
    aliases:
      - role_name
      - role
  type:
    description:
      - A Cloudera Manager Service role type to manage.
      - One of C(name) or C(type) is required.
    type: str
    aliases:
      - role_type
  parameters:
    description:
      - The role-specific configuration to set, i.e. role overrides.
      - To unset a parameter, use C(None) as the value.
    type: dict
    required: yes
    aliases:
      - params
  purge:
    description:
      - Flag for whether the declared parameters should append or overwrite any existing parameters.
      - To clear all parameters, set I(parameters={}), i.e. an empty dictionary, and I(purge=True).
    type: bool
    default: False
  view:
    description:
      - The view to return.
    type: str
    default: summary
    choices:
        - summary
        - full
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
- name: Update (append) Cloudera manager Service Host Monitor role parameters
  cloudera.cluster.cm_service_role_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    parameters:
      a_configuration: "schema://host:port"
      another_configuration: 234

- name: Reset a Cloudera manager Service Host Monitor role parameter
  cloudera.cluster.cm_service_role_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: "a-non-default-role-name"
    parameters:
      more_configuration: None

- name: Update (with purge) Cloudera manager Service Host Monitor role parameters
  cloudera.cluster.cluster_service_role_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    parameters:
      config_one: None
      config_two: ValueTwo
      config_three: 2345

- name: Reset all Cloudera manager Service Host Monitor role parameters
  cloudera.cluster.cluster_service_role_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    parameters: {}
    purge: true
"""

RETURN = r"""
config:
  description:
    - List of Cloudera Manager Service role configurations.
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

import json

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerMutableModule,
    ConfigListUpdates,
)

from cm_client import MgmtRolesResourceApi
from cm_client.rest import ApiException


class ClouderaManagerServiceRoleConfig(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClouderaManagerServiceRoleConfig, self).__init__(module)

        # Set the parameters
        self.name = self.get_param("name")
        self.type = self.get_param("type")
        self.params = self.get_param("parameters")
        self.purge = self.get_param("purge")
        self.view = self.get_param("view")

        # Initialize the return value
        self.changed = False
        self.diff = {}
        self.config = []

        # Execute the logic
        self.process()

    @ClouderaManagerMutableModule.handle_process
    def process(self):
        refresh = True
        role_api = MgmtRolesResourceApi(self.api_client)

        try:
            if self.name is None:
                role = next(
                    iter(
                        [r for r in role_api.read_roles().items if r.type == self.type]
                    ),
                    None,
                )
                if role is None:
                    self.module.fail_json(
                        msg=f"Unable to find Cloudera Manager Service role type '{self.type}"
                    )
                else:
                    self.name = role.name

            # For some reason, the call to read_roles() doesn't retrieve the configuration
            existing = role_api.read_role_config(self.name)
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg=json.loads(ex.body)["message"])
            else:
                raise ex

        updates = ConfigListUpdates(existing, self.params, self.purge)

        if updates.changed:
            self.changed = True

            if self.module._diff:
                self.diff = updates.diff

            if not self.module.check_mode:
                self.config = [
                    p.to_dict()
                    for p in role_api.update_role_config(
                        self.name,
                        message=self.message,
                        body=updates.config,
                    ).items
                ]

                if self.view == "full":
                    refresh = False

        if refresh:
            self.config = [
                p.to_dict()
                for p in role_api.read_role_config(self.name, view=self.view).items
            ]


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            name=dict(aliases=["role_name", "role"]),
            type=dict(aliases=["role_type"]),
            parameters=dict(type="dict", required=True, aliases=["params"]),
            purge=dict(type="bool", default=False),
            view=dict(
                default="summary",
                choices=["summary", "full"],
            ),
        ),
        required_one_of=[
            ["name", "type"],
        ],
        supports_check_mode=True,
    )

    result = ClouderaManagerServiceRoleConfig(module)

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
