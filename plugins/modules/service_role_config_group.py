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
module: service_role_config_group
short_description: Manage a cluster service role config group.
description:
  - Manage a cluster service role config group.
author:
  - "Webster Mudge (@wmudge)"
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
  name:
    description:
      - A role config group to manage.
      - If not defined, the module will target the I(base) role config group associated with the O(role_type).
    type: str
    aliases:
      - role_config_group_name
      - role_config_group
  role_type:
    description:
      - The role type defining the role config group.
      - To change the I(role_type) of an existing role config group, you must explicitly delete and recreate the role config group.
    type: str
    aliases:
      - type
  display_name:
    description:
      - The display name for this role config group in the Cloudera Manager UI.
  config:
    description:
      - The role config group configuration to set.
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
  skip_redacted:
    description:
      - Flag indicating if the declared configuration parameters and tags should skipped I(REDACTED) parameters during reconciliation.
      - If set, the module will not attempt to update any existing parameter with a I(REDACTED) value.
      - Otherwise, the parameter value will be overridden.
    type: bool
    default: False
    aliases:
      - redacted
  state:
    description:
      - The presence or absence of the role config group.
      - If any I(roles) are associated with role config group, you are not able to delete the group.
      - "NOTE: you cannot remove a C(base) role config group."
    type: str
    choices:
      - present
      - absent
    default: present
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - cloudera.cluster.message
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
  - module: cloudera.cluster.service_role_config_group_info
"""

EXAMPLES = r"""
- name: Create or update a role config group
  cloudera.cluster.service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: ZooKeeper
    name: Example-ZK-Server
    type: SERVER
    config:
      tickTime: 2500

- name: Create or update a role config group, purging undeclared parameters
  cloudera.cluster.service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: ZooKeeper
    name: Example-ZK-Server
    type: SERVER
    config:
      another_parameter: 12345
    purge: true

- name: Update the base role config group for a role type
  cloudera.cluster.service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: ZooKeeper
    # name: Leave blank to target the base role config group
    type: SERVER
    config:
      tickTime: 3500

- name: Reset the configuration of a role config group
  cloudera.cluster.service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: ZooKeeper
    name: Example-ZK-Server
    type: SERVER
    purge: true
"""

RETURN = r"""
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
    cluster_name:
      description:
        - The cluster name associated with the service of the role config group.
      type: str
      returned: always
    config:
      description: Set of configurations for the role config group.
      type: dict
      returned: when supported
    role_names:
      description:
        - List of role names associated with this role config group.
      type: list
      elements: str
      returned: when supported
"""

from cm_client import (
    ApiConfigList,
    ApiRoleConfigGroup,
    ApiRoleConfigGroupList,
    ClustersResourceApi,
    RoleConfigGroupsResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    reconcile_config_list_updates,
    ClouderaManagerMutableModule,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    create_role_config_group,
    parse_role_config_group_result,
    get_base_role_config_group,
)


class ClusterServiceRoleConfig(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClusterServiceRoleConfig, self).__init__(module)

        # Set the parameters
        self.cluster = self.get_param("cluster")
        self.service = self.get_param("service")
        self.name = self.get_param("name")
        self.role_type = self.get_param("role_type")
        self.display_name = self.get_param("display_name")
        self.config = self.get_param("config")
        self.purge = self.get_param("purge")
        self.skip_redacted = self.get_param("skip_redacted")
        self.state = self.get_param("state")

        # Initialize the return value
        self.changed = False
        self.diff = dict(before=dict(), after=dict())
        self.output = {}

        # Execute the logic
        self.process()

    @ClouderaManagerMutableModule.handle_process
    def process(self):
        # Confirm the presence of the cluster and service
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

        rcg_api = RoleConfigGroupsResourceApi(self.api_client)
        current = None
        current_roles = []

        # Retrieve the RCG and any associated roles
        try:
            if self.name:
                current = rcg_api.read_role_config_group(
                    cluster_name=self.cluster,
                    service_name=self.service,
                    role_config_group_name=self.name,
                )
            else:
                current = get_base_role_config_group(
                    self.api_client, self.cluster, self.service, self.role_type
                )

            current_roles = rcg_api.read_roles(
                cluster_name=self.cluster,
                service_name=self.service,
                role_config_group_name=current.name,
            ).items
        except ApiException as ex:
            if ex.status != 404:
                raise ex

        if self.state == "absent":
            if current:
                self.changed = True

                if current.base:
                    self.module.fail_json(
                        msg="Deletion failed. Role config group is a base (default) group."
                    )

                if current_roles:
                    self.module.fail_json(
                        msg="Deletion failed. Role config group has existing role associations."
                    )

                if self.module._diff:
                    self.diff = dict(
                        before=dict(
                            **parse_role_config_group_result(current),
                        ),
                        after={},
                    )

                if not self.module.check_mode:
                    rcg_api.delete_role_config_group(
                        cluster_name=self.cluster,
                        role_config_group_name=current.name,
                        service_name=self.service,
                    )

        elif self.state == "present":
            if current:
                # Check for role type changes
                if self.role_type and self.role_type != current.role_type:
                    self.module.fail_json(
                        msg="Invalid role type. To change the role type of an existing role config group, please destroy and recreate the role config group with the designated role type."
                    )

                payload = ApiRoleConfigGroup(
                    name=current.name, role_type=current.role_type
                )

                # Check for display name changes
                if self.display_name and self.display_name != current.display_name:
                    self.changed = True

                    if self.module._diff:
                        self.diff["before"].update(display_name=current.display_name)
                        self.diff["after"].update(display_name=self.display_name)

                    payload.display_name = self.display_name

                # Reconcile configurations
                if self.config or self.purge:
                    if self.config is None:
                        self.config = dict()

                    (
                        updated_config,
                        config_before,
                        config_after,
                    ) = reconcile_config_list_updates(
                        current.config,
                        self.config,
                        self.purge,
                        self.skip_redacted,
                    )

                    if config_before or config_after:
                        self.changed = True

                        if self.module._diff:
                            self.diff["before"].update(config=config_before)
                            self.diff["after"].update(config=config_after)

                        payload.config = updated_config

                # Execute changes if needed
                if self.changed and not self.module.check_mode:
                    current = rcg_api.update_role_config_group(
                        cluster_name=self.cluster,
                        service_name=self.service,
                        role_config_group_name=current.name,
                        message=self.message,
                        body=payload,
                    )
            else:
                if self.role_type is None:
                    self.module.fail_json(
                        msg="Role config group needs to be created, but is missing required arguments: role_type"
                    )

                self.changed = True

                # Create the RCG
                payload = create_role_config_group(
                    api_client=self.api_client,
                    cluster_name=self.cluster,
                    service_name=self.service,
                    name=self.name,
                    role_type=self.role_type,
                    display_name=self.display_name,
                    config=self.config,
                )

                # payload = ApiRoleConfigGroup(
                #     name=self.name,
                #     role_type=self.role_type,
                # )

                # if self.display_name:
                #     payload.display_name = self.display_name

                # # Set the configuration
                # if self.config:
                #     payload.config = ConfigListUpdates(
                #         ApiConfigList(items=[]), self.config, self.purge
                #     ).config

                if self.module._diff:
                    self.diff = dict(
                        before={},
                        after=dict(
                            **parse_role_config_group_result(payload),
                        ),
                    )

                if not self.module.check_mode:
                    current = rcg_api.create_role_config_groups(
                        cluster_name=self.cluster,
                        service_name=self.service,
                        body=ApiRoleConfigGroupList([payload]),
                    ).items[0]

            # Prepare output
            if self.changed:
                self.output = parse_role_config_group_result(
                    rcg_api.read_role_config_group(
                        cluster_name=self.cluster,
                        service_name=self.service,
                        role_config_group_name=current.name,
                    )
                )
            else:
                self.output = parse_role_config_group_result(current)

            self.output.update(
                role_names=[r.name for r in current_roles],
            )
        else:
            self.module.fail_json(msg="Invalid state: " + self.state)


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            service=dict(required=True, aliases=["service_name"]),
            name=dict(aliases=["role_config_group_name", "role_config_group"]),
            display_name=dict(),
            role_type=dict(aliases=["type"]),
            config=dict(type="dict", aliases=["params", "parameters"]),
            purge=dict(type="bool", default=False),
            skip_redacted=dict(type="bool", default=False, aliases=["redacted"]),
            state=dict(choices=["present", "absent"], default="present"),
        ),
        required_one_of=[
            ["name", "role_type"],
        ],
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
