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
module: cm_service_role_config_group_info
short_description: Retrieve information about Cloudera Management service role config groups.
description:
  - Gather information about Cloudera Manager service role config groups.
author:
  - Webster Mudge (@wmudge)
version_added: "5.0.0"
options:
  type:
    description:
      - The role type defining the role config group.
    type: str
    aliases:
      - role_type
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - ansible.builtin.action_common_attributes
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
  - module: cloudera.cluster.cm_service_role_config_group
"""

EXAMPLES = r"""
- name: Gather details of an individual Cloudera Manager service role config group.
  cloudera.cluster.cm_service_role_config_group_info:
    host: "example.cloudera.host"
    username: "will_jordan"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
  register: cm_output

- name: Gather details of all Cloudera Manager service role config groups.
  cloudera.cluster.cm_service_role_config_group_info:
    host: "example.cloudera.host"
    username: "will_jordan"
    password: "S&peR4Ec*re"
  register: cm_output
"""

RETURN = r"""
role_config_groups:
  description: List of Cloudera Manager service role config groups.
  type: list
  elements: dict
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
    ClouderaManagerModule,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    parse_role_config_group_result,
    get_mgmt_base_role_config_group,
)


class ClouderaServiceRoleConfigGroupInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaServiceRoleConfigGroupInfo, self).__init__(module)

        # Set the parameters
        self.type = self.get_param("type")

        # Initialize the return values
        self.output = list()

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
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
        if self.type:
            try:
                current = get_mgmt_base_role_config_group(self.api_client, self.type)
            except ApiException as ex:
                if ex.status != 404:
                    raise ex

            if current is not None:
                result = parse_role_config_group_result(current)
                result.update(
                    role_names=[r.name for r in rcg_api.read_roles(current.name).items],
                )
                self.output.append(result)
        else:

            def process_result(rcg: ApiRoleConfigGroup) -> dict:
                result = parse_role_config_group_result(rcg)
                result.update(
                    role_names=[r.name for r in rcg_api.read_roles(rcg.name).items],
                )
                return result

            self.output = [
                process_result(r)
                for r in rcg_api.read_role_config_groups().items
                if r.base
            ]


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            type=dict(aliases=["role_type"]),
        ),
        supports_check_mode=False,
    )

    result = ClouderaServiceRoleConfigGroupInfo(module)

    output = dict(
        changed=False,
        role_config_groups=result.output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
