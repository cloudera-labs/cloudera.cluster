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

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
    parse_role_config_group_result,
)

from cm_client import (
    ClustersResourceApi,
    RoleConfigGroupsResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: service_role_config_group_info
short_description: Retrieve information about a cluster service role config group or groups
description:
  - Gather details about a role config group or groups of a service in a CDP cluster.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
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
  role_config_group:
    description:
      - The role config group to examine.
      - If undefined, the module will return all role config groups for the service.
      - If the role config group does not exist, the module will return an empty result.
    type: str
    required: yes
    aliases:
      - role_config_group
      - name
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
"""

EXAMPLES = r"""
---
- name: Gather the configuration details for a cluster service role
  cloudera.cluster.service_role_config_info:
    host: "example.cloudera.internal"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: knox
    role: GATEWAY
  
- name: Gather the configuration details in 'full' for a cluster service role
  cloudera.cluster.service_role_config_info:
    host: "example.cloudera.internal"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: ecs
    role: ECS
    view: full
"""

RETURN = r"""
---
config:
  description:
    - List of service role config groups.
  type: list
  elements: dict
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
        - List of role names managed by this role config group.
      type: list
      elements: str
      returned: when supported
"""


class ClusterServiceRoleConfigGroupInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClusterServiceRoleConfigGroupInfo, self).__init__(module)

        # Set the parameters
        self.cluster = self.get_param("cluster")
        self.service = self.get_param("service")
        self.role_config_group = self.get_param("role_config_group")

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
                self.cluster, self.service
            )
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg="Service does not exist: " + self.service)
            else:
                raise ex

        api_instance = RoleConfigGroupsResourceApi(self.api_client)

        results = []
        if self.role_config_group:
            try:
                results = [
                    api_instance.read_role_config_group(
                        cluster_name=self.cluster,
                        role_config_group_name=self.role_config_group,
                        service_name=self.service,
                    )
                ]
            except ApiException as e:
                if e.status != 404:
                    raise e
        else:
            results = api_instance.read_role_config_groups(
                cluster_name=self.cluster,
                service_name=self.service,
            ).items

        for r in results:
            # Get role membership
            roles = api_instance.read_roles(
                cluster_name=self.cluster,
                service_name=self.service,
                role_config_group_name=r.name,
            )

            self.output.append(
                {
                    **parse_role_config_group_result(r),
                    "role_names": [r.name for r in roles.items],
                }
            )


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            service=dict(required=True, aliases=["service_name"]),
            role_config_group=dict(aliases=["role_config_group", "name"]),
        ),
        supports_check_mode=True,
    )

    result = ClusterServiceRoleConfigGroupInfo(module)

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
