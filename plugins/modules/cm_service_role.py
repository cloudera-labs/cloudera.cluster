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
module: cm_service_role
short_description: Manage a Cloudera Manager Service role
description:
  - Manage a Cloudera Manager Service role
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm-client
options:
  cms_hostname:
    description:
      - The hostname of a cluster instance for the role.
      - Mutually exclusive with I(cluster_host_id).
    type: str
    aliases:
      - cluster_host
  cms_host_id:
    description:
      - The host ID of a cluster instance for the role.
      - Mutually exclusive with I(cluster_hostname).
    type: str
  type:
    description:
      - A role type for the role.
      - Required if the I(state) creates a new role.
    type: str
    aliases:
      - role_type
  role_config_group:
    description:
      - A role type for the role.
      - Required if the I(state) creates a new role.
    type: str
    aliases:
      - role_type
  config:
    description:
      - The role configuration to set, i.e. overrides.
      - To unset a parameter, use C(None) as the value.
    type: dict
    aliases:
      - params
      - parameters
  maintenance:
    description:
      - Flag for whether the role should be in maintenance mode.
    type: bool
    aliases:
      - maintenance_mode
  tags:
    description:
      - A set of tags applied to the role.
      - To unset a tag, use C(None) as its value.
    type: dict
  purge:
    description:
      - Flag for whether the declared role tags should append or overwrite any existing tags.
      - To clear all tags, set I(tags={}), i.e. an empty dictionary, and I(purge=True).
    type: bool
    default: False
  state:
    description:
      - The state of the role.
      - Note, if the declared state is invalid for the role, for example, the role is a C(HDFS GATEWAY), the module will return an error.
    type: str
    default: present
    choices:
      - present
      - absent
      - restarted
      - started
      - stopped
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  platform:
    platforms: all
"""

EXAMPLES = r"""
- name: Establish a service role (auto-generated name)
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    type: GATEWAY
    cluster_hostname: worker-01.cloudera.internal

- name: Establish a service role (defined name)
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    type: GATEWAY
    name: example-gateway
    cluster_hostname: worker-01.cloudera.internal

- name: Set a service role to maintenance mode
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    name: example-gateway
    maintenance: yes

- name: Update (append) tags to a service role
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    name: example-gateway
    tags:
      tag_one: value_one
      tag_two: value_two

- name: Set (purge) tags to a service role
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    cluster: example-cluster
    service: example-hdfs
    name: example-gateway
    tags:
      tag_three: value_three
    purge: yes

- name: Remove all tags on a service role
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    name: example-gateway
    tags: {}
    purge: yes

- name: Start a service role
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    name: example-gateway
    state: started

- name: Force a restart to a service role
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    name: example-gateway
    state: restarted

- name: Start a service role
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    name: example-gateway
    state: started

- name: Remove a service role
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    name: example-gateway
    state: absent
"""

RETURN = r"""
role:
  description: Details about the service role.
  type: dict
  contains:
    name:
      description: The cluster service role name.
      type: str
      returned: always
    type:
      description: The cluster service role type.
      type: str
      returned: always
      sample:
        - NAMENODE
        - DATANODE
        - TASKTRACKER
    host_id:
      description: The unique ID of the cluster host.
      type: str
      returned: always
    service_name:
      description: The name of the cluster service, which uniquely identifies it in a cluster.
      type: str
      returned: always
    role_state:
      description: State of the cluster service role.
      type: str
      returned: always
      sample:
        - HISTORY_NOT_AVAILABLE
        - UNKNOWN
        - STARTING
        - STARTED
        - STOPPING
        - STOPPED
        - NA
    commission_state:
      description: Commission state of the cluster service role.
      type: str
      returned: always
    health_summary:
      description: The high-level health status of the cluster service role.
      type: str
      returned: always
      sample:
        - DISABLED
        - HISTORY_NOT_AVAILABLE
        - NOT_AVAILABLE
        - GOOD
        - CONCERNING
        - BAD
    config_staleness_status:
      description: Status of configuration staleness for the cluster service role.
      type: str
      returned: always
      sample:
        - FRESH
        - STALE_REFRESHABLE
        - STALE
    health_checks:
      description: Lists all available health checks for cluster service role.
      type: list
      elements: dict
      returned: when supported
      contains:
        name:
          description: Unique name of this health check.
          type: str
          returned: always
        summary:
          description: The high-level health status of the health check.
          type: str
          returned: always
          sample:
            - DISABLED
            - HISTORY_NOT_AVAILABLE
            - NOT_AVAILABLE
            - GOOD
            - CONCERNING
            - BAD
        explanation:
          description: The explanation of this health check.
          type: str
          returned: when supported
        suppressed:
          description:
            - Whether this health check is suppressed.
            - A suppressed health check is not considered when computing the role's overall health.
          type: bool
          returned: when supported
    maintenance_mode:
      description: Whether the cluster service role is in maintenance mode.
      type: bool
      returned: when supported
    maintenance_owners:
      description: The list of objects that trigger this service to be in maintenance mode.
      type: list
      elements: str
      returned: when supported
      sample:
        - CLUSTER
        - SERVICE
        - ROLE
        - HOST
        - CONTROL_PLANE
    role_config_group_name:
      description: The name of the cluster service role config group, which uniquely identifies it in a Cloudera Manager installation.
      type: str
      returned: when supported
    tags:
      description: The dictionary of tags for the cluster service role.
      type: dict
      returned: when supported
    zoo_keeper_server_mode:
      description:
        - The Zookeeper server mode for this cluster service role.
        - Note that for non-Zookeeper Server roles, this will be C(null).
      type: str
      returned: when supported
"""

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerMutableModule,
    ConfigListUpdates,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    create_role,
    parse_role_result,
)

from cm_client import (
    ApiBulkCommandList,
    ApiRole,
    ApiRoleList,
    ApiRoleNameList,
    ApiRoleState,
    MgmtRolesResourceApi,
    MgmtRoleCommandsResourceApi,
    MgmtServiceResourceApi,
)
from cm_client.rest import ApiException


class ClouderaManagerServiceRole(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClouderaManagerServiceRole, self).__init__(module)

        # Set the parameters
        self.cluster_hostname = self.get_param("cluster_hostname")
        self.cluster_host_id = self.get_param("cluster_host_id")
        self.config = self.get_param("config")
        self.maintenance = self.get_param("maintenance")
        self.type = self.get_param("type")
        self.state = self.get_param("state")
        self.purge = self.get_param("purge")

        # Initialize the return values
        self.changed = False
        self.diff = dict(before={}, after={})
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

        self.role_api = MgmtRolesResourceApi(self.api_client)

        current = None

        # Discover the role by its type
        try:
            current = next(
                iter(
                    [r for r in self.role_api.read_roles().items if r.type == self.type]
                ),
                None,
            )
            current.config = self.role_api.read_role_config(current.name)
        except ApiException as ex:
            if ex.status != 404:
                raise ex

        # If deleting, do so and exit
        if self.state == "absent":
            if current:
                self.deprovision_role(current)

        # Otherwise, manage the configuration and state
        elif self.state in ["present", "restarted", "started", "stopped"]:
            # If it is a new role
            if not current:
                new_role = create_role(
                    api_client=self.api_client,
                    role_type=self.type,
                    hostname=self.cluster_hostname,
                    host_id=self.cluster_host_id,
                    config=self.config,
                )
                current = self.provision_role(new_role)
            # # If it exists, but the type has changed, destroy and rebuild completely
            # elif self.type and self.type != current.type:
            #     new_role = create_role(
            #         api_client=self.api_client,
            #         role_type=self.type,
            #         hostname=current.host_ref.hostname,
            #         host_id=current.host_ref.host_id,
            #         config=self.config
            #     )
            #     current = self.reprovision_role(current, new_role)
            # Else it exists, so address any changes
            else:
                # Handle role override configurations
                if self.config or self.purge:
                    updates = ConfigListUpdates(current.config, self.config, self.purge)

                    if updates.changed:
                        self.changed = True

                        if self.module._diff:
                            self.diff["before"].update(config=updates.diff["before"])
                            self.diff["after"].update(config=updates.diff["after"])

                        if not self.module.check_mode:
                            self.role_api.update_role_config(
                                current.name,
                                message=self.message,
                                body=updates.config,
                            )

            # Handle maintenance mode
            if (
                self.maintenance is not None
                and self.maintenance != current.maintenance_mode
            ):
                self.changed = True

                if self.module._diff:
                    self.diff["before"].update(
                        maintenance_mode=current.maintenance_mode
                    )
                    self.diff["after"].update(maintenance_mode=self.maintenance)

                if not self.module.check_mode:
                    if self.maintenance:
                        maintenance_cmd = self.role_api.enter_maintenance_mode(
                            current.name
                        )
                    else:
                        maintenance_cmd = self.role_api.exit_maintenance_mode(
                            current.name
                        )

                    if maintenance_cmd.success is False:
                        self.module.fail_json(
                            msg=f"Unable to set Maintenance mode to '{self.maintenance}': {maintenance_cmd.result_message}"
                        )

            # Handle the various states
            if self.state == "started" and current.role_state not in [
                ApiRoleState.STARTED
            ]:
                self.changed = True

                if self.module._diff:
                    self.diff["before"].update(role_state=current.role_state)
                    self.diff["after"].update(role_state="STARTED")

                if not self.module.check_mode:
                    self.handle_commands(
                        MgmtRoleCommandsResourceApi(self.api_client).start_command(
                            body=ApiRoleNameList(items=[current.name]),
                        )
                    )

            elif self.state == "stopped" and current.role_state not in [
                ApiRoleState.STOPPED,
                ApiRoleState.NA,
            ]:
                self.changed = True

                if self.module._diff:
                    self.diff["before"].update(role_state=current.role_state)
                    self.diff["after"].update(role_state="STOPPED")

                if not self.module.check_mode:
                    self.handle_commands(
                        MgmtRoleCommandsResourceApi(self.api_client).stop_command(
                            body=ApiRoleNameList(items=[current.name]),
                        )
                    )

            elif self.state == "restarted":
                self.changed = True

                if self.module._diff:
                    self.diff["before"].update(role_state=current.role_state)
                    self.diff["after"].update(role_state="STARTED")

                if not self.module.check_mode:
                    self.handle_commands(
                        MgmtRoleCommandsResourceApi(self.api_client).restart_command(
                            body=ApiRoleNameList(items=[current.name]),
                        )
                    )

            # If there are changes, get a refresh read
            if self.changed:
                refresh = self.role_api.read_role(current.name)
                refresh.config = self.role_api.read_role_config(current.name)
                self.output = parse_role_result(refresh)
            # Otherwise return the existing
            else:
                self.output = parse_role_result(current)
        else:
            self.module.fail_json(msg=f"Invalid state: {self.state}")

    def provision_role(self, role: ApiRole) -> ApiRole:
        self.changed = True

        if self.module._diff:
            self.diff = dict(
                before={},
                after=role.to_dict(),
            )

        if not self.module.check_mode:
            created_role = next(
                (
                    iter(
                        self.role_api.create_roles(
                            body=ApiRoleList(items=[role]),
                        ).items
                    )
                ),
                {},
            )
            if not created_role:
                self.module.fail_json(
                    msg="Unable to create new role", role=to_native(role.to_dict())
                )

    def reprovision_role(self, existing_role: ApiRole, new_role: ApiRole) -> ApiRole:
        self.changed = True

        if self.module._diff:
            self.diff = dict(
                before=existing_role.to_dict(),
                after=new_role.to_dict(),
            )

        if not self.module.check_mode:
            self.role_api.delete_role(existing_role.name)

            rebuilt_role = next(
                (
                    iter(
                        self.role_api.create_roles(
                            body=ApiRoleList(items=[new_role]),
                        ).items
                    )
                ),
                {},
            )
            if not rebuilt_role:
                self.module.fail_json(
                    msg="Unable to recreate role, " + existing_role.name,
                    role=to_native(rebuilt_role.to_dict()),
                )

    def deprovision_role(self, role: ApiRole):
        self.changed = True

        if self.module._diff:
            self.diff = dict(before=role.to_dict(), after=dict())

        if not self.module.check_mode:
            self.role_api.delete_role(role.name)

    # def xxxcreate_role(self) -> ApiRole:
    #     # Check for required creation parameters
    #     missing_params = []

    #     if self.type is None:
    #         missing_params.append("type")

    #     if self.cluster_hostname is None and self.cluster_host_id is None:
    #         missing_params += ["cluster_hostname", "cluster_host_id"]

    #     if missing_params:
    #         self.module.fail_json(
    #             msg=f"Unable to create new role, missing required arguments: {', '.join(sorted(missing_params)) }"
    #         )

    #     # Set up the role
    #     payload = ApiRole(type=str(self.type).upper())

    #     # Name
    #     if self.name:
    #         payload.name = self.name # No name allows auto-generation

    #     # Host assignment
    #     host_ref = get_host_ref(self.api_client, self.cluster_hostname, self.cluster_host_id)

    #     if host_ref is None:
    #         self.module.fail_json(msg="Invalid host reference")
    #     else:
    #         payload.host_ref = host_ref

    #     # Role override configurations
    #     if self.config:
    #         payload.config = ApiConfigList(items=[ApiConfig(name=k, value=v) for k, v in self.config.items()])

    #     # Execute the creation
    #     self.changed = True

    #     if self.module._diff:
    #         self.diff = dict(
    #             before={},
    #             after=payload.to_dict(),
    #         )

    #     if not self.module.check_mode:
    #         created_role = next(
    #             (
    #                 iter(
    #                     self.role_api.create_roles(
    #                         body=ApiRoleList(items=[payload]),
    #                     ).items
    #                 )
    #             ),
    #             {},
    #         )

    # # Maintenance
    # if self.maintenance:
    #     if self.module._diff:
    #         self.diff["after"].update(maintenance_mode=True)

    #     maintenance_cmd = self.role_api.enter_maintenance_mode(
    #         created_role.name
    #     )

    #     if maintenance_cmd.success is False:
    #         self.module.fail_json(
    #             msg=f"Unable to set Maintenance mode to '{self.maintenance}': {maintenance_cmd.result_message}"
    #         )

    # if self.state in ["started", "restarted"]:
    #     self.handle_commands(MgmtRoleCommandsResourceApi(self.api_client).start_command(
    #         body=ApiRoleNameList(items=[created_role.name]),
    #     ))

    # elif self.state == "stopped":
    #     self.handle_commands(MgmtRoleCommandsResourceApi(self.api_client).stop_command(
    #         body=ApiRoleNameList(items=[created_role.name]),
    #     ))

    # if refresh:
    #     self.output = parse_role_result(
    #         self.role_api.read_role(
    #             self.cluster,
    #             created_role.name,
    #             self.service,
    #             view="full",
    #         )
    #     )
    # else:
    #     self.output = parse_role_result(created_role)

    def handle_commands(self, commands: ApiBulkCommandList):
        if commands.errors:
            error_msg = "\n".join(commands.errors)
            self.module.fail_json(msg=error_msg)

        for c in commands.items:
            # Not in parallel, but should only be a single command
            self.wait_command(c)


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            cluster_hostname=dict(aliases=["cluster_host"]),
            cluster_host_id=dict(),
            maintenance=dict(type="bool", aliases=["maintenance_mode"]),
            config=dict(type="dict", aliases=["params", "parameters"]),
            purge=dict(type="bool", default=False),
            type=dict(required=True),
            state=dict(
                default="present",
                choices=["present", "absent", "restarted", "started", "stopped"],
            ),
        ),
        mutually_exclusive=[
            ["cluster_hostname", "cluster_host_id"],
        ],
        supports_check_mode=True,
    )

    result = ClouderaManagerServiceRole(module)

    output = dict(
        changed=result.changed,
        role=result.output,
    )

    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
