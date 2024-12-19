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
module: cm_service_role_config_group
short_description: Manage a Cloudera Manager Service role config group.
description:
  - Manage a Cloudera Manager Service role config group.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm-client
options:
  type:
    description:
      - The role type defining the role config group.
    type: str
    required: True
    aliases:
      - role_type
  display_name:
    description:
      - The display name for this role config group in the Cloudera Manager UI.
  config:
    description:
      - The role configuration to set.
      - To unset a parameter, use C(None) as the value.
    type: dict
    aliases:
      - params
      - parameters
  purge:
    description:
      - Flag indicating whether to reset configuration parameters to only the declared entries.
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
"""

EXAMPLES = r"""
- name: Update the configuration of a Cloudera Manager Service role config group
  cloudera.cluster.cm_service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    parameters:
      some_parameter: True

- name: Update the configuration of a Cloudera Manager Service role config group, purging undeclared parameters
  cloudera.cluster.cm_service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    parameters:
      another_parameter: 3456
    purge: yes

- name: Reset the configuration of a Cloudera Manager Service role config group
  cloudera.cluster.cm_service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    parameters: {}
    purge: yes

- name: Set the display name of a Cloudera Manager Service role config group
  cloudera.cluster.cm_service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    display_name: A new name
"""

RETURN = r"""
role_config_group:
  description:
    - A Cloudera Manager Service role config group.
  type: dict
  returned: always
  contains:
    name:
      description:
        - The unique name of this role config group.
      type: str
      returned: always
    role_type:
      description:
        - The type of the roles in this group.
      type: str
      returned: always
    base:
      description:
        - Flag indicating whether this is a base group.
      type: bool
      returned: always
    display_name:
      description:
        - A user-friendly name of the role config group, as would have been shown in the web UI.
      type: str
      returned: when supported
    service_name:
      description:
        - The service name associated with this role config group.
      type: str
      returned: always
    role_names:
      description:
        - List of role names associated with this role config group.
      type: list
      elements: str
      returned: when supported
    config:
      description:
        - List of configurations.
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

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerMutableModule,
    ConfigListUpdates,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    BaseRoleConfigGroupDiscoveryException,
    parse_role_config_group_result,
    get_mgmt_base_role_config_group,
)

from cm_client import (
    ApiRoleConfigGroup,
    MgmtRoleConfigGroupsResourceApi,
    MgmtServiceResourceApi,
)
from cm_client.rest import ApiException


class ClouderaManagerServiceRoleConfigGroup(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClouderaManagerServiceRoleConfigGroup, self).__init__(module)

        # Set the parameters
        self.type = self.get_param("type")
        self.display_name = self.get_param("display_name")
        self.config = self.get_param("config", default=dict())
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
                self.module.fail_json(msg="Cloudera Management Service does not exist")
            else:
                raise ex

        rcg_api = MgmtRoleConfigGroupsResourceApi(self.api_client)

        # Retrieve the base RCG (the _only_ RCG for CMS roles)
        try:
            existing = get_mgmt_base_role_config_group(self.api_client, self.type)
        except ApiException as ex:
            if ex.status != 404:
                raise ex
        except BaseRoleConfigGroupDiscoveryException as be:
            self.module.fail_json(
                msg=f"Unable to find Cloudera Manager Service base role config group for role type '{self.type}'"
            )

        payload = ApiRoleConfigGroup()

        # Update display name
        if self.display_name and self.display_name != existing.display_name:
            self.changed = True

            if self.module._diff:
                self.diff["before"].update(display_name=existing.display_name)
                self.diff["after"].update(display_name=self.display_name)

            payload.display_name = self.display_name

        # Reconcile configurations
        if self.config or self.purge:
            updates = ConfigListUpdates(existing.config, self.config, self.purge)

            if updates.changed:
                self.changed = True

                if self.module._diff:
                    self.diff["before"].update(config=updates.diff["before"])
                    self.diff["after"].update(config=updates.diff["after"])

                payload.config = updates.config

        # Execute changes if needed
        if self.changed and not self.module.check_mode:
            self.output = parse_role_config_group_result(
                rcg_api.update_role_config_group(
                    existing.name,
                    message=self.message,
                    body=payload,
                )
            )
        else:
            self.output = parse_role_config_group_result(existing)

        # Report on any role associations
        self.output.update(
            role_names=[r.name for r in rcg_api.read_roles(existing.name).items]
        )


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            display_name=dict(),
            type=dict(required=True, aliases=["role_type"]),
            config=dict(type="dict", aliases=["params", "parameters"]),
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
