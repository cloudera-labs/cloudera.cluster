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
    ClouderaManagerMutableModule,
    parse_role_config_group_result,
)

from cm_client import (
    ApiRoleConfigGroup,
    ApiRoleConfigGroupList,
    ApiRoleNameList,
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
module: service_role_config_group
short_description: Manage a cluster service role config group.
description:
  - Manage a cluster service role config group.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
options:
  cluster:
    description:
      - The associated cluster.
    type: str
    required: True
    aliases:
      - cluster_name
  service:
    description:
      - The associated service.
    type: str
    required: True
    aliases:
      - service_name
  role_config_group:
    description:
      - A role config group to manage.
    type: str
    required: True
    aliases:
      - role_config_group_name
      - name
  role_type:
    description:
      - The role type defining the role config group.
      - I(role_type) is only valid during creation.
      - To change the I(role_type) of an existing role config group, you must explicitly delete and recreate the role config group.
    type: str
    required: False
    aliases:
      - type
  display_name:
    description:
      - The display name for this role config group in the Cloudera Manager UI.
  purge:
    description:
      - Flag indicating whether to reset role associations to only the declared roles.
    type: bool
    required: False
    default: False
  roles:
    description:
      - A list of roles associated, i.e. using, the role config group.
      - If I(purge=False), any new roles will be moved to use the role config group.
      - If I(purge=True), any roles not specified in the list will be reset to the C(base) role config group for the service.
    type: list
    elements: str
    required: False
    aliases:
      - role_association
      - role_membership
      - membership
  state:
    description:
      - The presence or absence of the role config group.
      - On I(state=absent), any associated role will be moved to the service's default group, i.e. the C(base) role config group.
      - NOTE: you cannot remove a C(base) role config group.
    type: str
    required: False
    choices:
      - present
      - absent
    default: present
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - cloudera.cluster.message
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
"""

EXAMPLES = r"""
---
- name: Create a role config group
  cloudera.cluster.service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: HDFS
    role_config_group: Example-DATANODE
    type: DATANODE

- name: Create or update a role config group with role associations
  cloudera.cluster.service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: HDFS
    type: DATANODE
    role_config_group: Example-DATANODE
    roles:
      - hdfs-DATANODE-a9a5b7d344404d8a304ff4b3779679a1

- name: Append a role association to a role config group
  cloudera.cluster.cluster_service_role_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-service
    role_config_group: Example-DATANODE
    roles:
      - hdfs-DATANODE-7f3a9da5805a46e3100bae67424355ac # Now two roles

- name: Update (purge) role associations to a role config group
  cloudera.cluster.cluster_service_role_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-service
    role_config_group: Example-DATANODE
    roles:
      - hdfs-DATANODE-7f3a9da5805a46e3100bae67424355ac # Now only one role
    purge: yes

- name: Reset all role associations to a role config group
  cloudera.cluster.cluster_service_role_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-service
    role_config_group: Example-DATANODE
    roles: []
    purge: yes

- name: Remove a role config group
  cloudera.cluster.service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: HDFS
    role_config_group: Example-DATANODE
    state: absent
-
"""

RETURN = r"""
---
role_config_group:
  description:
    - A service role config group.
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
"""


class ClusterServiceRoleConfig(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClusterServiceRoleConfig, self).__init__(module)

        # Set the parameters
        self.cluster = self.get_param("cluster")
        self.service = self.get_param("service")
        self.role_config_group = self.get_param("role_config_group")
        self.role_type = self.get_param("role_type")
        self.display_name = self.get_param("display_name")
        self.roles = self.get_param("roles")
        self.purge = self.get_param("purge")
        self.state = self.get_param("state")

        # Initialize the return value
        self.changed = False
        self.diff = {}
        self.output = {}

        # Execute the logic
        self.process()

    @ClouderaManagerMutableModule.handle_process
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
        existing = None
        existing_roles = []

        try:
            existing = api_instance.read_role_config_group(
                cluster_name=self.cluster,
                role_config_group_name=self.role_config_group,
                service_name=self.service,
            )
            existing_roles = api_instance.read_roles(
                cluster_name=self.cluster,
                role_config_group_name=self.role_config_group,
                service_name=self.service,
            )
        except ApiException as ex:
            if ex.status != 404:
                raise ex

        if self.state == "absent":
            if existing:
                self.changed = True

                if self.module._diff:
                    self.diff = dict(
                        before=dict(roles=[r.name for r in existing_roles.items]),
                        after={},
                    )

                if not self.module.check_mode:
                    if existing_roles:
                        api_instance.move_roles_to_base_group(
                            cluster_name=self.cluster,
                            service_name=self.service,
                            body=ApiRoleNameList(
                                [r.name for r in existing_roles.items]
                            ),
                        )

                    api_instance.delete_role_config_group(
                        cluster_name=self.cluster,
                        role_config_group_name=self.role_config_group,
                        service_name=self.service,
                    )

        elif self.state == "present":
            if existing:
                if self.role_type and self.role_type != existing.role_type:
                    self.module.fail_json(
                        msg="Invalid role type. To change the role type of an existing role config group, please destroy and recreate the role config group with the designated role type."
                    )

                if self.display_name and self.display_name != existing.display_name:
                    self.changed = True

                    if self.module._diff:
                        self.diff["before"].update(display_name=existing.display_name)
                        self.diff["after"].update(display_name=self.display_name)

                    if not self.module.check_mode:
                        api_instance.update_role_config_group(
                            cluster_name=self.cluster,
                            role_config_group_name=self.role_config_group,
                            service_name=self.service,
                            message=self.message,
                            body=ApiRoleConfigGroup(display_name=self.display_name),
                        )

                if self.roles is not None:
                    existing_role_names = set([r.name for r in existing_roles.items])
                    roles_add = set(self.roles) - existing_role_names

                    if self.purge:
                        roles_del = existing_role_names - set(self.roles)
                    else:
                        roles_del = []

                    if self.module._diff:
                        self.diff["before"].update(roles=existing_role_names)
                        self.diff["after"].update(roles=roles_add)

                    if roles_add:
                        self.changed = True
                        if not self.module.check_mode:
                            api_instance.move_roles(
                                cluster_name=self.cluster,
                                role_config_group_name=self.role_config_group,
                                service_name=self.service,
                                body=ApiRoleNameList(list(roles_add)),
                            )

                    if roles_del:
                        self.changed = True
                        if not self.module.check_mode:
                            api_instance.move_roles_to_base_group(
                                cluster_name=self.cluster,
                                service_name=self.service,
                                body=ApiRoleNameList(list(roles_del)),
                            )

            else:
                self.changed = True

                if self.role_type is None:
                    self.module.fail_json(msg="missing required arguments: role_type")

                if self.module._diff:
                    self.diff = dict(
                        before={},
                        after=dict(roles=self.roles),
                    )

                if not self.module.check_mode:
                    payload = ApiRoleConfigGroup(
                        name=self.role_config_group,
                        role_type=self.role_type,
                    )

                    if self.display_name:
                        payload.display_name = self.display_name

                    api_instance.create_role_config_groups(
                        cluster_name=self.cluster,
                        service_name=self.service,
                        body=ApiRoleConfigGroupList([payload]),
                    )

                    if self.roles:
                        api_instance.move_roles(
                            cluster_name=self.cluster,
                            role_config_group_name=self.role_config_group,
                            service_name=self.service,
                            body=ApiRoleNameList(self.roles),
                        )

            if self.changed:
                self.output = parse_role_config_group_result(
                    api_instance.read_role_config_group(
                        cluster_name=self.cluster,
                        role_config_group_name=self.role_config_group,
                        service_name=self.service,
                    )
                )

                self.output.update(
                    role_names=[
                        r.name
                        for r in api_instance.read_roles(
                            cluster_name=self.cluster,
                            role_config_group_name=self.role_config_group,
                            service_name=self.service,
                        ).items
                    ]
                )

            else:
                self.output = {
                    **parse_role_config_group_result(existing),
                    "role_names": [r.name for r in existing_roles.items],
                }

        else:
            self.module.fail_json(msg="Invalid state: " + self.state)


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            service=dict(required=True, aliases=["service_name"]),
            role_config_group=dict(
                required=True, aliases=["role_config_group_name", "name"]
            ),
            display_name=dict(),
            role_type=dict(aliases=["type"]),
            roles=dict(
                type="list",
                elements="str",
                aliases=["role_association", "role_membership", "membership"],
            ),
            purge=dict(type="bool", default=False),
            state=dict(choices=["present", "absent"], default="present"),
        ),
        supports_check_mode=True,
    )

    result = ClusterServiceRoleConfig(module)

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
