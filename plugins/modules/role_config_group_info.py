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
module: role_config_group_info
short_description: Retrieve information about a cluster service role config group or groups
description:
  - Gather details about a role config group or groups of a service in a CDP cluster.
author:
  - "Webster Mudge (@wmudge)"
version_added: "4.4.0"
options:
  cluster:
    description:
      - The associated cluster.
    type: str
    required: yes
    aliases:
      - cluster_name
  service:
    description:
      - The associated service.
    type: str
    required: yes
    aliases:
      - service_name
  type:
    description:
      - The role type defining the role config group(s).
      - If specified, will return all role config groups for the type.
      - Mutually exclusive with O(name).
    type: str
    aliases:
      - role_type
  name:
    description:
      - The role config group to examine.
      - If defined, the module will return the role config group.
      - If the role config group does not exist, the module will return an empty result.
      - Mutually exclusive with O(type).
    type: str
    aliases:
      - role_config_group
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - ansible.builtin.action_common_attributes
attributes:
  check_mode:
    support: full
requirements:
  - cm-client
seealso:
  - module: cloudera.cluster.role_config_group
"""

EXAMPLES = r"""
- name: Gather the configuration details for all role config groups for a service
  cloudera.cluster.role_config_group_info:
    host: "example.cloudera.internal"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: knox

- name: Gather the configuration details for a base role config group
  cloudera.cluster.role_config_group_info:
    host: "example.cloudera.internal"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: knox
    type: GATEWAY

- name: Gather the configuration details for a custom role config group
  cloudera.cluster.role_config_group_info:
    host: "example.cloudera.internal"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: knox
    name: custom_rcg_knox_gateway
"""

RETURN = r"""
role_config_groups:
  description:
    - List of cluster service role config groups.
  type: list
  elements: dict
  returned: always
  contains:
    name:
      description: Name (identifier) of the role config group.
      type: str
      returned: always
    role_type:
      description: The type of the roles in this role config group.
      type: str
      returned: always
    base:
      description: Flag indicating whether this is a base role config group.
      type: bool
      returned: always
    display_name:
      description: A user-friendly name of the role config group, as would have been shown in the web UI.
      type: str
      returned: when supported
    service_name:
      description: The service name associated with this role config group.
      type: str
      returned: always
    role_names:
      description: List of role names (identifiers) associated with this role config group.
      type: list
      elements: str
      returned: when supported
"""

from cm_client import (
    ClustersResourceApi,
    RoleConfigGroupsResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    parse_role_config_group_result,
)


class RoleConfigGroupInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(RoleConfigGroupInfo, self).__init__(module)

        # Set the parameters
        self.cluster = self.get_param("cluster")
        self.service = self.get_param("service")
        self.type = self.get_param("type")
        self.name = self.get_param("name")

        # Initialize the return values
        self.output = []

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        try:
            ClustersResourceApi(self.api_client).read_cluster(self.cluster)
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg="Cluster does not exist: " + self.cluster)
            else:
                raise ex

        try:
            ServicesResourceApi(self.api_client).read_service(
                self.cluster,
                self.service,
            )
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg="Service does not exist: " + self.service)
            else:
                raise ex

        rcg_api = RoleConfigGroupsResourceApi(self.api_client)

        results = []

        # If given a specific RCG
        if self.name:
            try:
                results = [
                    rcg_api.read_role_config_group(
                        cluster_name=self.cluster,
                        role_config_group_name=self.name,
                        service_name=self.service,
                    ),
                ]
            except ApiException as e:
                if e.status != 404:
                    raise e
        # Else if given a RCG type
        elif self.type:
            results = [
                r
                for r in rcg_api.read_role_config_groups(
                    cluster_name=self.cluster,
                    service_name=self.service,
                ).items
                if r.role_type == self.type
            ]
        # Else get all RCG entries for the given service
        else:
            results = rcg_api.read_role_config_groups(
                cluster_name=self.cluster,
                service_name=self.service,
            ).items

        # Get role membership
        for r in results:
            roles = rcg_api.read_roles(
                cluster_name=self.cluster,
                service_name=self.service,
                role_config_group_name=r.name,
            )

            self.output.append(
                {
                    **parse_role_config_group_result(r),
                    "role_names": [r.name for r in roles.items],
                },
            )


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            service=dict(required=True, aliases=["service_name"]),
            type=dict(aliases=["role_type"]),
            name=dict(aliases=["role_config_group"]),
        ),
        mutually_exclusive=[["type", "name"]],
        supports_check_mode=True,
    )

    result = RoleConfigGroupInfo(module)

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
