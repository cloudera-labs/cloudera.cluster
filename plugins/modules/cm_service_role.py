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
module: cm_service_role
short_description: Manage a Cloudera Manager Service role
description:
  - Manage a Cloudera Manager Service role.
author:
  - Webster Mudge (@wmudge)
options:
  cluster_hostname:
    description:
      - The hostname of an instance for the role.
      - If the hostname is different that the existing host for the O(type), the role will be destroyed and rebuilt on the declared host.
      - Mutually exclusive with O(cluster_host_id).
    type: str
    aliases:
      - cluster_host
  cluster_host_id:
    description:
      - The host ID of an instance for the role.
      - If the host ID is different that the existing host for the O(type), the role will be destroyed and rebuilt on the declared host.
      - Mutually exclusive with O(cluster_hostname).
    type: str
  type:
    description:
      - A role type for the role.
    type: str
    required: True
    aliases:
      - role_type
  config:
    description:
      - The role configuration to set, i.e. role overrides, for the instance.
      - To unset a parameter, use V(None) as the value.
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
  purge:
    description:
      - Flag for whether the declared role configurations should append or overwrite any existing configurations.
      - To clear all role configurations, set O(config={}), i.e. an empty dictionary, or omit entirely, and set O(purge=True).
    type: bool
    default: False
  state:
    description:
      - The state of the role.
      - Note, if the declared state is invalid for the role, the module will return an error.
      - Note, V(restarted) is always force a change of state of the role.
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
  - module: cloudera.cluster.cm_service_role_config_group
"""

EXAMPLES = r"""
- name: Establish a Cloudera Manager Service role
  cloudera.cluster.cm_service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    cluster_hostname: worker-01.cloudera.internal

- name: Set a Cloudera Manager Service role to maintenance mode
  cloudera.cluster.cm_service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    maintenance: yes

- name: Update (append) role configurations to a Cloudera Manager Service role
  cloudera.cluster.cm_service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    config:
      some_config: value_one
      another_config: value_two

- name: Set (purge) role configurations to a Cloudera Manager Service role
  cloudera.cluster.cm_service_role:
    host: example.cloudera.com
    username: "jane_smith"
    type: HOSTMONITOR
    config:
      yet_another_config: value_three
    purge: yes

- name: Remove all role configurations on a Cloudera Manager Service role
  cloudera.cluster.cm_service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    purge: yes

- name: Start a Cloudera Manager Service role
  cloudera.cluster.cm_service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    state: started

- name: Force a restart to a Cloudera Manager Service role
  cloudera.cluster.cm_service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    state: restarted

- name: Remove a Cloudera Manager Service role
  cloudera.cluster.cm_service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
    state: absent
"""

RETURN = r"""
role:
  description: Details about the Cloudera Manager service role.
  type: dict
  returned: always
  contains:
    commission_state:
      description: Commission state of the Cloudera Manager service role.
      type: str
      returned: always
      sample:
        - COMMISSIONED
        - DECOMMISSIONING
        - DECOMMISSIONED
        - UNKNOWN
        - OFFLINING
        - OFFLINED
    config:
      description: Role override configuration for the Cloudera Manager service.
      type: dict
      returned: optional
    config_staleness_status:
      description: Status of configuration staleness for the Cloudera Manager service role.
      type: str
      returned: always
      sample:
        - FRESH
        - STALE_REFRESHABLE
        - STALE
    ha_status:
      description: High-availability status for the Cloudera Manager service.
      type: str
      returned: optional
      sample:
        - ACTIVE
        - STANDBY
        - UNKNOWN
    health_checks:
      description: List of all available health checks for Cloudera Manager service role.
      type: list
      elements: dict
      returned: optional
      contains:
        explanation:
          description: The explanation of this health check.
          type: str
          returned: optional
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
        suppressed:
          description:
            - Whether this health check is suppressed.
            - A suppressed health check is not considered when computing the role's overall health.
          type: bool
          returned: optional
    health_summary:
      description: The high-level health status of the Cloudera Manager service role.
      type: str
      returned: always
      sample:
        - DISABLED
        - HISTORY_NOT_AVAILABLE
        - NOT_AVAILABLE
        - GOOD
        - CONCERNING
        - BAD
    host_id:
      description: The unique ID of the cluster host.
      type: str
      returned: always
    maintenance_mode:
      description: Whether the Cloudera Manager service role is in maintenance mode.
      type: bool
      returned: always
    maintenance_owners:
      description: List of objects that trigger the Cloudera Manager service role to be in maintenance mode.
      type: list
      elements: str
      returned: optional
      sample:
        - CLUSTER
        - SERVICE
        - ROLE
        - HOST
        - CONTROL_PLANE
    name:
      description:
        - The Cloudera Manager service role name.
        - Note, this is an auto-generated name and cannot be changed.
      type: str
      returned: always
    role_config_group_name:
      description: The name of the Cloudera Manager Service role config group, which uniquely identifies it in a Cloudera Manager installation.
      type: str
      returned: always
    role_state:
      description: State of the Cloudera Manager service role.
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
    service_name:
      description: The name of the Cloudera Manager service, which uniquely identifies it in a deployment.
      type: str
      returned: always
    tags:
      description: Set of tags for the Cloudera Manager service role.
      type: dict
      returned: optional
    type:
      description: The Cloudera Manager service role type.
      type: str
      returned: always
      sample:
        - HOSTMONITOR
        - ALERTPUBLISHER
        - SERVICEMONITOR
        - REPORTSMANAGER
        - EVENTSERVER
    zoo_keeper_server_mode:
      description:
        - The Zookeeper server mode for this Cloudera Manager service role.
        - Note that for non-Zookeeper Server roles, this will be V(null).
      type: str
      returned: optional
"""

from collections.abc import Callable

from cm_client import (
    ApiBulkCommandList,
    ApiCommand,
    ApiRole,
    ApiRoleList,
    ApiRoleNameList,
    ApiRoleState,
    MgmtRolesResourceApi,
    MgmtRoleCommandsResourceApi,
    MgmtServiceResourceApi,
)
from cm_client.rest import ApiException

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerMutableModule,
    ConfigListUpdates,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    create_role,
    parse_role_result,
    read_cm_role,
)


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
        self.output = dict()

        # Execute the logic
        self.process()

    @ClouderaManagerMutableModule.handle_process
    def process(self):

        service_api = MgmtServiceResourceApi(self.api_client)
        role_api = MgmtRolesResourceApi(self.api_client)
        role_cmd_api = MgmtRoleCommandsResourceApi(self.api_client)

        # Confirm that CMS is present
        try:
            service_api.read_service()
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg="Cloudera Management service does not exist")
            else:
                raise ex

        current = None

        # Discover the role by its type
        try:
            current = read_cm_role(api_client=self.api_client, role_type=self.type)
        except ApiException as ex:
            if ex.status != 404:
                raise ex

        # If deleting, do so and exit
        if self.state == "absent":
            if current:
                self.deprovision_role(role_api, current)

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
                current = self.provision_role(role_api, new_role)
                self.handle_maintenance(role_api, current)
            # Else if it exists, but the host has changed, destroy and rebuild completely
            elif (
                current
                and (
                    self.cluster_hostname is not None
                    and self.cluster_hostname != current.host_ref.hostname
                )
                or (
                    self.cluster_host_id is not None
                    and self.cluster_host_id != current.host_ref.host_id
                )
            ):
                if self.config:
                    new_config = self.config
                else:
                    new_config = {c.name: c.value for c in current.config.items}

                new_role = create_role(
                    api_client=self.api_client,
                    role_type=current.type,
                    hostname=self.cluster_hostname,
                    host_id=self.cluster_host_id,
                    config=new_config,
                )
                current = self.reprovision_role(role_api, current, new_role)
                self.handle_maintenance(role_api, current)
            # Else it exists, so address any changes
            else:
                self.handle_maintenance(role_api, current)

                # Handle role override configurations
                if self.config or self.purge:
                    if self.config is None:
                        self.config = dict()

                    updates = ConfigListUpdates(current.config, self.config, self.purge)

                    if updates.changed:
                        self.changed = True

                        if self.module._diff:
                            self.diff["before"].update(config=updates.diff["before"])
                            self.diff["after"].update(config=updates.diff["after"])

                        if not self.module.check_mode:
                            role_api.update_role_config(
                                current.name,
                                message=self.message,
                                body=updates.config,
                            )

            # Handle the various states
            if self.state == "started" and current.role_state not in [
                ApiRoleState.STARTED
            ]:
                self.exec_role_command(
                    current, ApiRoleState.STARTED, role_cmd_api.start_command
                )
            elif self.state == "stopped" and current.role_state not in [
                ApiRoleState.STOPPED,
                ApiRoleState.NA,
            ]:
                self.exec_role_command(
                    current, ApiRoleState.STOPPED, role_cmd_api.stop_command
                )
            elif self.state == "restarted":
                self.exec_role_command(
                    current, ApiRoleState.STARTED, role_cmd_api.restart_command
                )

            # If there are changes, get a fresh read
            if self.changed:
                refresh = role_api.read_role(current.name)
                refresh.config = role_api.read_role_config(current.name)
                self.output = parse_role_result(refresh)
            # Otherwise return the existing
            else:
                self.output = parse_role_result(current)
        else:
            self.module.fail_json(msg=f"Invalid state: {self.state}")

    def exec_role_command(
        self, role: ApiRole, value: str, cmd: Callable[[ApiRoleNameList], ApiCommand]
    ):
        self.changed = True
        if self.module._diff:
            self.diff["before"].update(role_state=role.role_state)
            self.diff["after"].update(role_state=value)

        if not self.module.check_mode:
            self.handle_commands(cmd(body=ApiRoleNameList(items=[role.name])))

    def handle_maintenance(self, role_api: MgmtRolesResourceApi, role: ApiRole) -> None:
        if self.maintenance is not None and self.maintenance != role.maintenance_mode:
            self.changed = True

            if self.module._diff:
                self.diff["before"].update(maintenance_mode=role.maintenance_mode)
                self.diff["after"].update(maintenance_mode=self.maintenance)

            if not self.module.check_mode:
                if self.maintenance:
                    maintenance_cmd = role_api.enter_maintenance_mode(role.name)
                else:
                    maintenance_cmd = role_api.exit_maintenance_mode(role.name)

                if maintenance_cmd.success is False:
                    self.module.fail_json(
                        msg=f"Unable to set Maintenance mode to '{self.maintenance}': {maintenance_cmd.result_message}"
                    )

    def provision_role(self, role_api: MgmtRolesResourceApi, role: ApiRole) -> ApiRole:
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
                        role_api.create_roles(
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
            return created_role

    def reprovision_role(
        self, role_api: MgmtRolesResourceApi, existing_role: ApiRole, new_role: ApiRole
    ) -> ApiRole:
        self.changed = True

        if self.module._diff:
            self.diff = dict(
                before=existing_role.to_dict(),
                after=new_role.to_dict(),
            )

        if not self.module.check_mode:
            role_api.delete_role(existing_role.name)

            rebuilt_role = next(
                (
                    iter(
                        role_api.create_roles(
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
            return rebuilt_role
        else:
            return existing_role

    def deprovision_role(self, role_api: MgmtRolesResourceApi, role: ApiRole) -> None:
        self.changed = True

        if self.module._diff:
            self.diff = dict(before=parse_role_result(role), after=dict())

        if not self.module.check_mode:
            role_api.delete_role(role.name)

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
            type=dict(required=True, aliases=["role_type"]),
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
