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
module: cm_service_role_config_group_config
short_description: Manage the configuration of a Cloudera Manager Service role config group.
description:
  - Manage the configuration details of a role config group of the Cloudera Manager Service.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm-client
options:
  name:
    description:
      - A role config group name to manage.
      - One of C(name) or C(type) is required.
    type: str
    aliases:
      - role_config_group
  type:
    description:
      - The role type of the role config group to manage.
      - Retrieves the default role config group for the given role type.
      - One of C(name) or C(type) is required.
    type: str
    aliases:
      - role_type
  parameters:
    description:
      - The role configuration to set.
      - To unset a parameter, use C(None) as the value.
    type: dict
    required: yes
    aliases:
      - params
  view:
    description:
      - The view to materialize.
    type: str
    default: summary
    choices:
        - summary
        - full
extends_documentation_fragment:
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
- name: Update (append) several role config group parameters for a Cloudera Manager Service role type
  cloudera.cluster.cm_service_role_config_group_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    parameters:
      a_configuration: "schema://host:port"
      another_configuration: 234

- name: Reset a role config group parameter for a Cloudera Manager Service role type
  cloudera.cluster.cm_service_role_config_group_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    parameters:
      some_conf: None

- name: Update (purge) role config group parameters (by name) for a Cloudera Manager Service role
  cloudera.cluster.service_role_config_group_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: "a-non-default-rcg"
    parameters:
      config_one: ValueOne
      config_two: 4567
    purge: yes

- name: Reset all role config group parameters for a Cloudera Manager Service role type
  cloudera.cluster.service_role_config_group_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    parameters: {}
    purge: yes
"""

RETURN = r"""
config:
  description:
    - List of configurations for a Cloudera Manager Service role config group.
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
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    BaseRoleConfigGroupDiscoveryException,
    get_mgmt_base_role_config_group,
)

from cm_client import MgmtRoleConfigGroupsResourceApi
from cm_client.rest import ApiException


class ClouderaManagerServiceRoleConfigGroupConfig(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClouderaManagerServiceRoleConfigGroupConfig, self).__init__(module)

        # Set the parameters
        self.name = self.get_param("name")
        self.type = self.get_param("type")
        self.params = self.get_param("parameters")
        self.purge = self.get_param("purge")
        self.view = self.get_param("view")

        # Initialize the return values
        self.changed = False
        self.diff = {}
        self.config = []

        # Execute the logic
        self.process()

    @ClouderaManagerMutableModule.handle_process
    def process(self):
        refresh = True
        rcg_api = MgmtRoleConfigGroupsResourceApi(self.api_client)

        try:
            if self.name is None:
                rcg = get_mgmt_base_role_config_group(self.api_client, self.type)
                self.name = rcg.name

            existing = rcg_api.read_config(self.name)
        except ApiException as ae:
            if ae.status == 404:
                self.module.fail_json(msg=json.loads(ae.body)["message"])
            else:
                raise ae
        except BaseRoleConfigGroupDiscoveryException as be:
            self.module.fail_json(
                msg=f"Unable to find Cloudera Manager Service base role config group for role type '{self.type}'"
            )

        updates = ConfigListUpdates(existing, self.params, self.purge)

        if updates.changed:
            self.changed = True

            if self.module._diff:
                self.diff = updates.diff

            if not self.module.check_mode:
                self.config = [
                    p.to_dict()
                    for p in rcg_api.update_config(
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
                for p in rcg_api.read_config(self.name, view=self.view).items
            ]


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            name=dict(aliases=["role_config_group"]),
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

    result = ClouderaManagerServiceRoleConfigGroupConfig(module)

    output = dict(
        changed=result.changed,
        config=result.config,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
