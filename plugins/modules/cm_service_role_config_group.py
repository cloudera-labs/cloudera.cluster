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
module: cm_service_role_config_group
short_description: Manage a Cloudera Manager Service role config group.
description:
  - Manage a Cloudera Manager Service role config group.
author:
  - Webster Mudge (@wmudge)
options:
  type:
    description:
      - The role type defining the role config group.
    type: str
    required: yes
    aliases:
      - role_type
  display_name:
    description:
      - The display name for this role config group.
  config:
    description:
      - The role configuration to set.
      - To unset a parameter, use V(None) as the value.
    type: dict
    aliases:
      - params
      - parameters
  purge:
    description:
      - Whether to reset configuration parameters to only the declared entries.
    type: bool
    default: False
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - cloudera.cluster.message
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  platform:
    platforms: all
requirements:
  - cm-client
seealso:
  - module: cloudera.cluster.cm_service
  - module: cloudera.cluster.cm_service_role
  - module: cloudera.cluster.cm_service_role_config_group_info
"""

EXAMPLES = r"""
- name: Update the configuration of a Cloudera Manager service role config group
  cloudera.cluster.cm_service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    config:
      some_parameter: True

- name: Update the configuration of a Cloudera Manager service role config group, purging undeclared parameters
  cloudera.cluster.cm_service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    config:
      another_parameter: 3456
    purge: yes

- name: Reset the configuration of a Cloudera Manager service role config group
  cloudera.cluster.cm_service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    purge: yes
"""

RETURN = r"""
role_config_group:
  description: A Cloudera Manager service role config group.
  type: dict
  returned: always
  contains:
    base:
      description: Whether the role config group is a base group.
      type: bool
      returned: always
    config:
      description: Set of configurations for the role config group.
      type: dict
      returned: optional
    display_name:
      description: Display name of the role config group.
      type: str
      returned: always
    name:
      description: Name (identifier) of the role config group.
      type: str
      returned: always
    role_names:
      description: List of role names (identifiers) associated with this role config group.
      type: list
      elements: str
      returned: optional
    role_type:
      description: The type of the roles in this role config group.
      type: str
      returned: always
    service_name:
      description: Service name associated with this role config group.
      type: str
      returned: always
"""

from cm_client import (
    ApiRoleConfigGroup,
    MgmtRoleConfigGroupsResourceApi,
    MgmtServiceResourceApi,
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerMutableModule,
    ConfigListUpdates,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    parse_role_config_group_result,
    get_mgmt_base_role_config_group,
)


class ClouderaManagerServiceRoleConfigGroup(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClouderaManagerServiceRoleConfigGroup, self).__init__(module)

        # Set the parameters
        self.type = self.get_param("type")
        self.config = self.get_param("config")
        self.purge = self.get_param("purge")

        # Initialize the return value
        self.changed = False
        self.diff = dict(before=dict(), after=dict())
        self.output = {}

        # Execute the logic
        self.process()

    @ClouderaManagerMutableModule.handle_process
    def process(self):
        # Confirm that CMS is present
        try:
            MgmtServiceResourceApi(self.api_client).read_service()
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg="Cloudera Management service does not exist")
            else:
                raise ex

        rcg_api = MgmtRoleConfigGroupsResourceApi(self.api_client)

        # Retrieve the base RCG (the _only_ RCG for CMS roles)
        try:
            current = get_mgmt_base_role_config_group(self.api_client, self.type)
            if current is None:
                self.module.fail_json(
                    msg=f"Unable to find Cloudera Manager service base role config group for role type '{self.type}'"
                )
        except ApiException as ex:
            if ex.status != 404:
                raise ex

        # Reconcile configurations
        if self.config or self.purge:
            if self.config is None:
                self.config = dict()

            updates = ConfigListUpdates(current.config, self.config, self.purge)

            if updates.changed:
                self.changed = True

                if self.module._diff:
                    self.diff["before"].update(config=updates.diff["before"])
                    self.diff["after"].update(config=updates.diff["after"])

                # Execute changes if needed
                if not self.module.check_mode:
                    current = rcg_api.update_role_config_group(
                        current.name,
                        message=self.message,
                        body=ApiRoleConfigGroup(
                            name=current.name,
                            role_type=current.role_type,
                            config=updates.config,
                            display_name=current.display_name,
                        ),
                    )

        # Parse the results
        self.output = parse_role_config_group_result(current)

        # Report on any role associations
        self.output.update(
            role_names=[r.name for r in rcg_api.read_roles(current.name).items]
        )


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            type=dict(required=True, aliases=["role_type"]),
            config=dict(required=True, type="dict", aliases=["params", "parameters"]),
            purge=dict(type="bool", default=False),
        ),
        supports_check_mode=True,
    )

    result = ClouderaManagerServiceRoleConfigGroup(module)

    output = dict(
        changed=result.changed,
        role_config_group=result.output,
    )

    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
