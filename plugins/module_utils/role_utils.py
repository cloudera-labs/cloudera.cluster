# Copyright 2024 Cloudera, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A common functions for Cloudera Manager roles
"""

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    normalize_output,
    wait_commands,
    wait_bulk_commands,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.host_utils import (
    get_host_ref,
)

from cm_client import (
    ApiClient,
    ApiConfig,
    ApiConfigList,
    ApiEntityTag,
    ApiRole,
    ApiRoleList,
    ApiRoleConfigGroupRef,
    ApiRoleNameList,
    ApiRoleState,
    ServicesResourceApi,
    RoleCommandsResourceApi,
    RoleConfigGroupsResourceApi,
    RolesResourceApi,
    MgmtRolesResourceApi,
)


class RoleException(Exception):
    """General Exception type for Role management."""

    pass


class RoleHostNotFoundException(RoleException):
    pass


class RoleConfigGroupNotFoundException(RoleException):
    pass


class RoleMaintenanceStateException(RoleException):
    pass


class InvalidRoleTypeException(RoleException):
    pass


ROLE_OUTPUT = [
    "commission_state",
    "config_staleness_status",
    "ha_status",
    "health_checks",
    "health_summary",
    # "host_ref",
    "maintenance_mode",
    "maintenance_owners",
    "name",
    # "role_config_group_ref",
    "role_state",
    # "service_ref",
    "tags",
    "type",
    "zoo_keeper_server_mode",
]


def parse_role_result(role: ApiRole) -> dict:
    # Retrieve only the host_id, hostname, role_config_group, and service identifiers
    output = dict(
        host_id=role.host_ref.host_id,
        hostname=role.host_ref.hostname,
        role_config_group_name=role.role_config_group_ref.role_config_group_name,
        service_name=role.service_ref.service_name,
    )
    output.update(normalize_output(role.to_dict(), ROLE_OUTPUT))
    output.update(config={c.name: c.value for c in role.config.items})
    return output


def get_mgmt_roles(api_client: ApiClient, role_type: str) -> ApiRoleList:
    role_api = MgmtRolesResourceApi(api_client)
    return ApiRoleList(
        items=[r for r in role_api.read_roles().items if r.type == role_type]
    )


def read_role(
    api_client: ApiClient, cluster_name: str, service_name: str, role_name: str
) -> ApiRole:
    """Read a role for a cluster service and populates the role configuration.

    Args:
        api_client (ApiClient): Cloudera Manager API client
        cluster_name (str): Cluster name (identifier).
        service_name (str): Service name (identifier).
        role_name (str): Role name (identifier).

    Raises:
        ApiException:

    Returns:
        ApiRole: The Role object or None if the role is not found.
    """
    role_api = RolesResourceApi(api_client)
    role = role_api.read_role(
        cluster_name=cluster_name, service_name=service_name, role_name=role_name
    )
    if role is not None:
        role.config = role_api.read_role_config(
            cluster_name=cluster_name, service_name=service_name, role_name=role.name
        )
    return role


def read_roles(
    api_client: ApiClient,
    cluster_name: str,
    service_name: str,
    type: str = None,
    hostname: str = None,
    host_id: str = None,
    view: str = None,
) -> ApiRoleList:
    """Read roles for a cluster service. Optionally, filter by type, hostname, host ID.

    Args:
        api_client (ApiClient): Cloudera Manager API client
        cluster_name (str): Cluster name (identifier)
        service_name (str): Service name (identifier)
        type (str, optional): Role type. Defaults to None.
        hostname (str, optional): Cluster hostname. Defaults to None.
        host_id (str, optional): Cluster host ID. Defaults to None.
        view (str, optional): View to retrieve. Defaults to None.

    Raises:
        ApiException:

    Returns:
        ApiRoleList: List of Role objects
    """
    role_api = RolesResourceApi(api_client)

    payload = dict(
        cluster_name=cluster_name,
        service_name=service_name,
    )

    if view is not None:
        payload.update(view=view)

    filter = ";".join(
        [
            f"{f[0]}=={f[1]}"
            for f in [
                ("type", type),
                ("hostname", hostname),
                ("hostId", host_id),
            ]
            if f[1] is not None
        ]
    )

    if filter != "":
        payload.update(filter=filter)

    roles = role_api.read_roles(**payload).items

    # Remove filter from core payload
    payload.pop("filter", None)

    for r in roles:
        payload.update(role_name=r.name)
        r.config = role_api.read_role_config(**payload)

    return ApiRoleList(items=roles)


def read_roles_by_type(
    api_client: ApiClient, cluster_name: str, service_name: str, role_type: str
) -> ApiRoleList:
    role_api = RolesResourceApi(api_client)
    roles = [
        r
        for r in role_api.read_roles(cluster_name, service_name).items
        if r.type == role_type
    ]
    for r in roles:
        r.config = role_api.read_role_config(
            cluster_name=cluster_name,
            service_name=service_name,
            role_name=r.name,
        )
    return ApiRoleList(items=roles)


def read_cm_role(api_client: ApiClient, role_type: str) -> ApiRole:
    role_api = MgmtRolesResourceApi(api_client)
    role = next(
        iter([r for r in role_api.read_roles().items if r.type == role_type]),
        None,
    )
    if role is not None:
        role.config = role_api.read_role_config(role.name)
    return role


def read_cm_roles(api_client: ApiClient) -> ApiRoleList:
    role_api = MgmtRolesResourceApi(api_client)
    roles = role_api.read_roles().items
    for r in roles:
        r.config = role_api.read_role_config(role_name=r.name)
    return ApiRoleList(items=roles)


def create_role(
    api_client: ApiClient,
    role_type: str,
    hostname: str = None,
    host_id: str = None,
    config: dict = None,
    cluster_name: str = None,
    service_name: str = None,
    role_config_group: str = None,
    tags: dict = None,
) -> ApiRole:
    if (
        role_type.upper()
        not in ServicesResourceApi(api_client)
        .list_role_types(
            cluster_name=cluster_name,
            service_name=service_name,
        )
        .items
    ):
        raise InvalidRoleTypeException(
            f"Invalid role type '{role_type}' for service '{service_name}'"
        )

    # Set up the role type
    role = ApiRole(type=str(role_type).upper())

    # Host assignment
    host_ref = get_host_ref(api_client, hostname, host_id)
    if host_ref is None:
        raise RoleHostNotFoundException(
            f"Host not found: hostname='{hostname}', host_id='{host_id}'"
        )
    else:
        role.host_ref = host_ref

    # Role config group
    if role_config_group:
        rcg_api = RoleConfigGroupsResourceApi(api_client)
        rcg = rcg_api.read_role_config_group(
            cluster_name=cluster_name,
            service_name=service_name,
            role_config_group_name=role_config_group,
        )
        if rcg is None:
            raise RoleConfigGroupNotFoundException(
                f"Role config group not found: {role_config_group}"
            )
        else:
            role.role_config_group_ref = ApiRoleConfigGroupRef(rcg.name)

    # Role override configurations
    if config:
        role.config = ApiConfigList(
            items=[ApiConfig(name=k, value=v) for k, v in config.items()]
        )

    # Tags
    if tags:
        role.tags = [ApiEntityTag(k, v) for k, v in tags.items()]

    return role


def provision_service_role(
    api_client: ApiClient, cluster_name: str, service_name: str, role: ApiRole
) -> ApiRole:
    role_api = RolesResourceApi(api_client)

    provisioned_role = next(
        (
            iter(
                role_api.create_roles(
                    cluster_name=cluster_name,
                    service_name=service_name,
                    body=ApiRoleList(items=[role]),
                ).items
            )
        ),
        None,
    )

    if provisioned_role is None:
        return

    # Wait for any running commands like Initialize
    available_cmds = role_api.list_commands(
        cluster_name=cluster_name,
        service_name=service_name,
        role_name=provisioned_role.name,
    )

    running_cmds = role_api.list_active_commands(
        cluster_name=cluster_name,
        service_name=service_name,
        role_name=provisioned_role.name,
    )

    try:
        wait_commands(api_client=api_client, commands=running_cmds)
        return provisioned_role
    except Exception as e:
        raise RoleException(str(e))


def toggle_role_maintenance(
    api_client: ApiClient, role: ApiRole, maintenance: bool, check_mode: bool
) -> bool:
    role_api = RolesResourceApi(api_client)
    changed = False

    if maintenance and not role.maintenance_mode:
        changed = True
        cmd = role_api.enter_maintenance_mode
    elif not maintenance and role.maintenance_mode:
        changed = True
        cmd = role_api.exit_maintenance_mode

    if not check_mode and changed:
        maintenance_cmd = cmd(
            cluster_name=role.service_ref.cluster_name,
            service_name=role.service_ref.service_name,
            role_name=role.name,
        )

        if maintenance_cmd.success is False:
            raise RoleMaintenanceStateException(
                f"Unable to set Maintenance mode to '{maintenance}': {maintenance_cmd.result_message}"
            )

    return changed


def toggle_role_state(
    api_client: ApiClient, role: ApiRole, state: str, check_mode: bool
) -> ApiRoleState:
    role_cmd_api = RoleCommandsResourceApi(api_client)
    changed = None

    if state == "started" and role.role_state not in [ApiRoleState.STARTED]:
        changed = ApiRoleState.STARTED
        cmd = role_cmd_api.start_command
    elif state == "stopped" and role.role_state not in [
        ApiRoleState.STOPPED,
        ApiRoleState.NA,
    ]:
        changed = ApiRoleState.STOPPED
        cmd = role_cmd_api.stop_command
    elif state == "restarted":
        changed = ApiRoleState.STARTED
        cmd = role_cmd_api.restart_command

    if not check_mode and changed:
        exec_cmds = cmd(
            cluster_name=role.service_ref.cluster_name,
            service_name=role.service_ref.service_name,
            body=ApiRoleNameList(items=[role.name]),
        )
        wait_bulk_commands(api_client=api_client, commands=exec_cmds)

    return changed
