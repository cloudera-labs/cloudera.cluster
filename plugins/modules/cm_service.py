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
module: cm_service
short_description: Manage Cloudera Manager service roles
description:
  - Create or remove one or more Cloudera Manager service roles.
  - Start, stop or restart one or more Cloudera Manager service roles.
author:
  - "Ronald Suplina (@rsuplina)"
options:
  role:
    description:
      - A list of one or more service roles to be configured.
    type: list
    elements: str
    required: True
  purge:
    description:
      - Delete all current roles and setup only the roles provided
    type: bool
    required: False
    default: False
  state:
    description:
      - The desired state of roles
    type: str
    default: 'started'
    choices:
      - 'started'
      - 'stopped'
      - 'absent'
      - 'present'
      - 'restarted'
    required: False

requirements:
  - cm_client
"""

EXAMPLES = r"""
- name: Start Cloudera Manager service roles
  cloudera.cluster.cm_version:
    host: "10.10.10.10"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: "7180"
    purge: False
    state: "started"
    role: [ "SERVICEMONITOR" , "HOSTMONITOR", "EVENTSERVER", "ALERTPUBLISHER" ]
  register: cm_output

- name: Purge all roles then create and start new roles
  cloudera.cluster.cm_version:
    host: "10.10.10.10"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: "7180"
    purge: True
    state: "started"
    role: [ "SERVICEMONITOR" , "HOSTMONITOR", "EVENTSERVER", "ALERTPUBLISHER" ]
  register: cm_output

- name: Stop two Cloudera Manager service  roles
  cloudera.cluster.cm_version:
    host: "10.10.10.10"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: "7180"
    state: "stopped"
    role: [ "EVENTSERVER", "ALERTPUBLISHER" ]
  register: cm_output

- name: Remove Cloudera Manager service role
  cloudera.cluster.cm_version:
    host: "10.10.10.10"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: "7180"
    purge: False
    state: "absent"
    role: [ "ALERTPUBLISHER" ]
  register: cm_output
"""

RETURN = r"""
service:
    description: List of Cloudera Manager roles
    type: dict
    contains:
        name:
            description: The Cloudera Manager role name.
            type: str
            returned: optional
        type:
            description: The Cloudera Manager role type.
            type: str
            returned: optional
        serviceRef:
            description: Reference to a service.
            type: str
            returned: optional
        service_url:
            description: Role url for Cloudera Manager Role.
            type: str
            returned: optional
        hostRef:
            description: Reference to a host.
            type: str
            returned: optional
        role_state:
            description: State of the Cloudera Manager Role.
            type: str
            returned: optional
        commissionState:
            description: Commission state of the role.
            type: str
            returned: optional
        health_summary:
            description: Health of the Cloudera Manager Role.
            type: str
            returned: optional
        roleConfigGroupRef:
            description: Reference to role config groups.
            type: str
            returned: optional
        configStalenessStatus:
            description: Status of configuration staleness for Cloudera Manager Role.
            type: str
            returned: optional
        health_checks:
            description: Lists all available health checks for Cloudera Manager Service.
            type: dict
            returned: optional
        role_instances_url:
            description: Role instance url for Cloudera Manager Service.
            type: str
            returned: optional
        maintenance_mode:
            description: Maintance mode of Cloudera Manager Role.
            type: bool
            returned: optional
        maintenance_owners:
            description: List of Maintance owners for Cloudera Manager Service.
            type: list
            returned: optional
        entity_status:
            description: Health status of entities for Cloudera Manager Role.
            type: str
            returned: optional
        tags:
            description: List of tags for Cloudera Manager Role.
            type: list
            returned: optional
"""

from collections.abc import Callable

from cm_client import (
    ApiBulkCommandList,
    ApiCommand,
    ApiConfigList,
    ApiRoleList,
    ApiRoleConfigGroup,
    ApiService,
    ApiServiceState,
    MgmtRolesResourceApi,
    MgmtRoleConfigGroupsResourceApi,
    MgmtServiceResourceApi,
)
from cm_client.rest import ApiException

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerMutableModule,
    ConfigListUpdates,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.service_utils import (
    ServiceConfigUpdates,
    parse_service_result,
    read_cm_service,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    get_mgmt_base_role_config_group,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    create_role,
)


class ClouderaManagerService(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClouderaManagerService, self).__init__(module)

        # Set the parameters
        self.maintenance = self.get_param("maintenance")
        self.config = self.get_param("config")
        self.role_config_groups = self.get_param("role_config_groups")
        self.roles = self.get_param("roles")
        self.state = self.get_param("state")
        self.purge = self.get_param("purge")
        # self.view = self.get_param("view")

        # Initialize the return value
        self.changed = False
        self.output = dict()

        if self.module._diff:
            self.diff = dict(before=dict(), after=dict())
            self.before = dict()
            self.after = dict()
        else:
            self.diff = dict()

        # Execute the logic
        self.process()

    @ClouderaManagerMutableModule.handle_process
    def process(self):

        service_api = MgmtServiceResourceApi(self.api_client)
        role_api = MgmtRolesResourceApi(self.api_client)
        rcg_api = MgmtRoleConfigGroupsResourceApi(self.api_client)

        current = None

        # Discover the CM service and retrieve its configured dependents
        try:
            # TODO This is only used once... so revert
            current = read_cm_service(self.api_client)
            # current = service_api.read_service()
            # if current is not None:
            #     # Gather the service-wide configuration
            #     current.config = service_api.read_service_config()

            #     # Gather each role config group configuration
            #     for rcg in current.role_config_groups:
            #         rcg.config = rcg_api.read_config(role_config_group_name=rcg.name)

            #     # Gather each role configuration
            #     for role in current.roles:
            #         role.config = role_api.read_role_config(role_name=role.name)

        except ApiException as ex:
            if ex.status != 404:
                raise ex

        # If deleting, do so and exit
        if self.state == "absent":
            if current:
                self.changed = True

                if self.module._diff:
                    self.before = parse_service_result(current)

                if not self.module.check_mode:
                    service_api.delete_cms()

        # Otherwise, manage the configurations of the service, its role config
        # groups, its roles, and its state
        elif self.state in ["present", "restarted", "started", "stopped"]:
            # If it is a new service, create the initial service
            if not current:
                self.changed = True
                new_service = ApiService(type="MGMT")
                current = service_api.setup_cms(body=new_service)
                current.config = service_api.read_service_config()
                current.role_config_groups = []
                current.roles = []

            # Handle maintenance mode
            if (
                self.maintenance is not None
                and self.maintenance != current.maintenance_mode
            ):
                self.changed = True

                if self.module._diff:
                    self.before.update(maintenance_mode=current.maintenance_mode)
                    self.after.update(maintenance_mode=self.maintenance_mode)

                if not self.module.check_mode:
                    if self.maintenance:
                        maintenance_cmd = service_api.enter_maintenance_mode()
                    else:
                        maintenance_cmd = service_api.exit_maintenance_mode()

                if maintenance_cmd.success is False:
                    self.module.fail_json(
                        msg=f"Unable to set Maintenance mode to '{self.maintenance}': {maintenance_cmd.result_message}"
                    )

            # Handle service-wide changes
            if self.config or self.purge:
                if self.config is None:
                    self.config = dict()

                updates = ServiceConfigUpdates(current.config, self.config, self.purge)

                if updates.changed:
                    self.changed = True

                    if self.module._diff:
                        self.before.update(config=updates.before)
                        self.after.update(config=updates.after)

                    if not self.module.check_mode:
                        service_api.update_service_config(
                            message=self.message, body=updates.config
                        )

            # Manage role config groups (base only)
            if self.role_config_groups or self.purge:
                # Get existing role config groups (ApiRoleConfigGroup)
                current_rcgs_map = {
                    rcg.role_type: rcg for rcg in current.role_config_groups
                }

                # Get the incoming role config groups (dict)
                if self.role_config_groups is None:
                    incoming_rcgs_map = dict()
                else:
                    incoming_rcgs_map = {
                        rcg["type"]: rcg for rcg in self.role_config_groups
                    }

                # Create sets of each role config group by type
                current_set = set(current_rcgs_map.keys())
                incoming_set = set(incoming_rcgs_map.keys())

                # Update any existing role config groups
                for rcg_type in current_set & incoming_set:
                    existing_rcg = current_rcgs_map[rcg_type]
                    incoming_rcg = incoming_rcgs_map[rcg_type]

                    if incoming_rcg["config"] is None:
                        incoming_rcg["config"] = dict()

                    # TODO Consolidate into util function; see cm_service_role_config_group:279-302
                    payload = ApiRoleConfigGroup()

                    # Update display name
                    incoming_display_name = incoming_rcg.get("display_name")
                    if (
                        incoming_display_name is not None
                        and incoming_display_name != existing_rcg.display_name
                    ):
                        self.changed = True
                        payload.display_name = incoming_display_name

                    # Reconcile configurations
                    if existing_rcg.config or self.purge:
                        updates = ConfigListUpdates(
                            existing_rcg.config, incoming_rcg["config"], self.purge
                        )

                        if updates.changed:
                            self.changed = True

                            if self.module._diff:
                                rcg_diff["before"].update(config=updates.diff["before"])
                                rcg_diff["after"].update(config=updates.diff["after"])

                            payload.config = updates.config

                    # Execute changes if needed
                    if (
                        payload.display_name is not None or payload.config is not None
                    ) and not self.module.check_mode:
                        rcg_api.update_role_config_group(
                            existing_rcg.name, message=self.message, body=payload
                        )

                # Add any new role config groups
                for rcg_type in incoming_set - current_set:
                    self.changed = True

                    if self.module._diff:
                        rcg_diff = dict(before=dict(), after=dict())

                    existing_rcg = get_mgmt_base_role_config_group(
                        self.api_client, rcg_type
                    )
                    incoming_rcg = incoming_rcgs_map[rcg_type]

                    payload = ApiRoleConfigGroup()

                    incoming_display_name = incoming_rcg.get("display_name")
                    if incoming_display_name is not None:
                        if self.module._diff:
                            rcg_diff["before"].update(
                                display_name=existing_rcg.display_name
                            )
                            rcg_diff["after"].update(display_name=incoming_display_name)
                        payload.display_name = incoming_display_name

                    incoming_rcg_config = incoming_rcg.get("config")
                    if incoming_rcg_config:
                        updates = ConfigListUpdates(
                            existing_rcg.config, incoming_rcg_config, self.purge
                        )

                        if self.module._diff:
                            rcg_diff["before"].update(config=updates.diff["before"])
                            rcg_diff["after"].update(config=updates.diff["after"])

                        payload.config = updates.config
                    else:
                        payload.config = ApiConfigList()

                    if not self.module.check_mode:
                        rcg_api.update_role_config_group(
                            existing_rcg.name, message=self.message, body=payload
                        )

                # Remove any undeclared role config groups
                if self.purge:
                    for rcg_type in current_set - incoming_set:
                        self.changed = True

                        if self.module._diff:
                            rcg_diff = dict(before=dict(), after=dict())

                        existing_rcg = get_mgmt_base_role_config_group(
                            self.api_client, rcg_type
                        )

                        payload = ApiRoleConfigGroup(
                            display_name=f"mgmt-{rcg_type}-BASE"
                        )

                        updates = ConfigListUpdates(
                            existing_rcg.config, dict(), self.purge
                        )

                        if self.module._diff:
                            rcg_diff["before"].update(config=updates.diff["before"])
                            rcg_diff["after"].update(config=updates.diff["after"])

                        payload.config = updates.config

                        if not self.module.check_mode:
                            rcg_api.update_role_config_group(
                                existing_rcg.name, message=self.message, body=payload
                            )

            # Manage roles
            if self.roles or self.purge:
                # Get existing roles (ApiRole)
                current_roles_map = {r.type: r for r in current.roles}

                # Get incoming roles (dict)
                if self.roles is None:
                    incoming_roles_map = dict()
                else:
                    incoming_roles_map = {r["type"]: r for r in self.roles}

                # Create sets of the roles
                current_set = set(current_roles_map.keys())
                incoming_set = set(incoming_roles_map.keys())

                # Update any existing roles
                for role_type in current_set & incoming_set:
                    existing_role = current_roles_map[role_type]
                    incoming_role = incoming_roles_map[role_type]

                    if incoming_role["config"] is None:
                        incoming_role["config"] = dict()

                    # If the host has changed, destroy and rebuild completely
                    incoming_hostname = incoming_role.get("cluster_hostname")
                    incoming_host_id = incoming_role.get("cluster_host_id")
                    if (
                        incoming_hostname is not None
                        and incoming_hostname != existing_role.host_ref.hostname
                    ) or (
                        incoming_host_id is not None
                        and incoming_host_id != existing_role.host_ref.host_id
                    ):
                        self.changed = True

                        # Use the new configuration or copy from the existing
                        new_config = (
                            incoming_role["config"]
                            if incoming_role["config"]
                            else {c.name: c.value for c in existing_role.config.items}
                        )

                        new_role = create_role(
                            api_client=self.api_client,
                            role_type=existing_role.type,
                            hostname=incoming_hostname,
                            host_id=incoming_host_id,
                            config=new_config,
                        )

                        if not self.module.check_mode:
                            role_api.delete_role(existing_role.name)

                            rebuilt_role = next(
                                (
                                    iter(
                                        role_api.create_roles(
                                            body=ApiRoleList(items=[new_role])
                                        ).items
                                    )
                                ),
                                {},
                            )
                            if not rebuilt_role:
                                self.module.fail_json(
                                    msg="Unable to recreate role, "
                                    + existing_role.name,
                                    role=to_native(rebuilt_role.to_dict()),
                                )

                    # Else address any updates
                    else:
                        updates = ConfigListUpdates(
                            existing_role.config,
                            incoming_role["config"],
                            self.purge,
                        )

                        if updates.changed:
                            self.changed = True

                            if not self.module.check_mode:
                                role_api.update_role_config(
                                    role_name=existing_role.name,
                                    message=self.message,
                                    body=updates.config,
                                )

                # Add any new roles
                for role_type in incoming_set - current_set:
                    self.changed = True

                    incoming_role = incoming_roles_map[role_type]

                    new_role = create_role(
                        api_client=self.api_client,
                        role_type=incoming_role.get("type"),
                        hostname=incoming_role.get("cluster_hostname"),
                        host_id=incoming_role.get("cluster_host_id"),
                        config=incoming_role.get("config"),
                    )

                    if not self.module.check_mode:
                        created_role = next(
                            (
                                iter(
                                    role_api.create_roles(
                                        body=ApiRoleList(items=[new_role])
                                    ).items
                                )
                            ),
                            {},
                        )
                        if not created_role:
                            self.module.fail_json(
                                msg="Unable to create new role",
                                role=to_native(new_role.to_dict()),
                            )

                # Remove any undeclared roles if directed
                if self.purge:
                    for role_type in current_set - incoming_set:
                        self.changed = True

                        existing_role = current_roles_map[role_type]

                        if not self.module.check_mode:
                            role_api.delete_role(existing_role.name)

            # Handle various states
            if self.state == "started" and current.service_state not in [
                ApiServiceState.STARTED
            ]:
                self.exec_service_command(
                    current, ApiServiceState.STARTED, service_api.start_command
                )
            elif self.state == "stopped" and current.service_state not in [
                ApiServiceState.STOPPED,
                ApiServiceState.NA,
            ]:
                self.exec_service_command(
                    current, ApiServiceState.STOPPED, service_api.stop_command
                )
            elif self.state == "restarted":
                self.exec_service_command(
                    current, ApiServiceState.STARTED, service_api.restart_command
                )

            # If there are changes, get a fresh read
            if self.changed:
                refresh = read_cm_service(self.api_client)
                self.output = parse_service_result(refresh)
            # Otherwise, return the existing
            else:
                self.output = parse_service_result(current)
        else:
            self.module.fail_json(msg=f"Invalid state: {self.state}")

    def exec_service_command(
        self, service: ApiService, value: str, cmd: Callable[[None], ApiCommand]
    ):
        self.changed = True
        if self.module._diff:
            self.diff["before"].update(service_state=service.service_state)
            self.diff["after"].update(service_state=value)

        if not self.module.check_mode:
            self.wait_command(cmd())

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
            config=dict(type="dict", aliases=["params", "parameters"]),
            role_config_groups=dict(
                type="list",
                elements="dict",
                options=dict(
                    display_name=dict(),  # TODO Remove display_name as an option
                    type=dict(required=True, aliases=["role_type"]),
                    config=dict(
                        required=True, type="dict", aliases=["params", "parameters"]
                    ),
                ),
            ),
            roles=dict(
                type="list",
                elements="dict",
                options=dict(
                    cluster_hostname=dict(aliases=["cluster_host"]),
                    cluster_host_id=dict(),
                    config=dict(type="dict", aliases=["params", "parameters"]),
                    type=dict(required=True, aliases=["role_type"]),
                ),
                mutually_exclusive=[["cluster_hostname", "cluster_host_id"]],
            ),
            maintenance=dict(type="bool", aliases=["maintenance_mode"]),
            purge=dict(type="bool", default=False),
            state=dict(
                type="str",
                default="present",
                choices=["started", "stopped", "absent", "present", "restarted"],
            ),
        ),
        supports_check_mode=True,
    )

    result = ClouderaManagerService(module)

    output = dict(
        changed=result.changed,
        service=result.output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
