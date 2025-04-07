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
A common functions for service management
"""

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    normalize_output,
    resolve_parameter_updates,
    wait_command,
    wait_commands,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    create_role_config_group,
    parse_role_config_group_result,
    update_role_config_group,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    parse_role_result,
    InvalidRoleTypeException,
)

from cm_client import (
    ApiClient,
    ApiConfig,
    ApiConfigList,
    ApiEntityTag,
    ApiHost,
    ApiRole,
    ApiRoleConfigGroup,
    ApiRoleConfigGroupList,
    ApiRoleNameList,
    ApiService,
    ApiServiceConfig,
    ApiServiceList,
    ApiServiceState,
    ClustersResourceApi,
    HostsResourceApi,
    MgmtServiceResourceApi,
    MgmtRoleConfigGroupsResourceApi,
    MgmtRolesResourceApi,
    RoleConfigGroupsResourceApi,
    RolesResourceApi,
    ServicesResourceApi,
)

SERVICE_OUTPUT = [
    "client_config_staleness_status",
    # "cluster_ref",
    "config_staleness_status",
    "display_name",
    "health_checks",
    "health_summary",
    "maintenance_mode",
    "maintenance_owners",
    "name",
    "service_state",
    "service_version",
    "tags",
    "type",
]


class ServiceException(Exception):
    pass


class ServiceMaintenanceStateException(ServiceException):
    pass


class InvalidServiceTypeException(ServiceException):
    pass


def parse_service_result(service: ApiService) -> dict:
    # Retrieve only the cluster_name if it exists
    if service.cluster_ref is not None:
        output = dict(cluster_name=service.cluster_ref.cluster_name)
    else:
        output = dict(cluster_name=None)

    # Parse the service itself
    output.update(normalize_output(service.to_dict(), SERVICE_OUTPUT))

    # Parse the service-wide configurations
    if service.config is not None:
        output.update(config={c.name: c.value for c in service.config.items})

    # Parse the role config groups via util function
    if service.role_config_groups is not None:
        output.update(
            role_config_groups=[
                parse_role_config_group_result(rcg)
                for rcg in service.role_config_groups
            ]
        )

    # Parse the roles via util function
    if service.roles is not None:
        output.update(roles=[parse_role_result(r) for r in service.roles])

    return output


def read_service(
    api_client: ApiClient, cluster_name: str, service_name: str
) -> ApiService:
    """Read a cluster service and its role config group and role dependents.

    Args:
        api_client (ApiClient): _description_
        cluster_name (str): _description_
        service_name (str): _description_

    Returns:
        ApiService: _description_
    """
    service_api = ServicesResourceApi(api_client)
    rcg_api = RoleConfigGroupsResourceApi(api_client)
    role_api = RolesResourceApi(api_client)

    service = service_api.read_service(
        cluster_name=cluster_name, service_name=service_name
    )

    if service is not None:
        # Gather the service-wide configuration
        service.config = service_api.read_service_config(
            cluster_name=cluster_name, service_name=service_name
        )

        # Gather each role config group configuration
        service.role_config_groups = rcg_api.read_role_config_groups(
            cluster_name=cluster_name,
            service_name=service_name,
        ).items

        # Gather each role configuration
        if service.roles is not None:
            for role in service.roles:
                role.config = role_api.read_role_config(
                    cluster_name=cluster_name,
                    service_name=service_name,
                    role_name=role.name,
                )
        else:
            service.roles = list()

    return service


def create_service(
    api_client: ApiClient,
    name: str,
    type: str,
    cluster_name: str,
    display_name: str = None,
    config: dict = None,
    tags: dict = None,
    # role_config_groups: list[ApiRoleConfigGroup] = None,
    # roles: list[ApiRole] = None,
) -> ApiService:
    if (
        type.upper()
        not in ClustersResourceApi(api_client)
        .list_service_types(
            cluster_name=cluster_name,
        )
        .items
    ):
        raise InvalidServiceTypeException(
            f"Invalid service type '{type}' for cluster '{cluster_name}'"
        )

    # Set up the service basics
    service = ApiService(name=name, type=str(type).upper())

    if display_name:
        service.display_name = display_name

    # Service-wide configurations
    if config:
        service.config = ApiConfigList(
            items=[ApiConfig(name=k, value=v) for k, v in config.items()]
        )

    # Tags
    if tags:
        service.tags = [ApiEntityTag(k, v) for k, v in tags.items()]

    # # Role config groups
    # # TODO Use a role_config_group utility to marshal the ApiRoleConfigGroup list
    # # Keep the incoming type, but use it to create another via the utility call
    # # This includes passing in the role type as an external reference
    # if role_config_groups:
    #     available_types = ServicesResourceApi(api_client).list_role_types(
    #         cluster_name=cluster_name,
    #         service_name=name,
    #     ).items

    #     for rcg in role_config_groups:
    #         if rcg.role_type not in available_types:
    #             raise InvalidRoleType("Unable to find role type: " + rcg.role_type)

    #     service.role_config_groups = role_config_groups

    # # Roles
    # # TODO Use the create_role() utility to marshal the ApiRole list
    # # Keep the incoming ApiRole type, but use it to create another via the utility call
    # # Need to pass in the role types and role config groups as external references (the latter because they
    # # might be defined within the service)
    # # For the former, the reference replaces an inline lookup. For the latter, the reference is a initial
    # # lookup and then a fallback to the inline lookup
    # # This might not work, as the references might fail because the service is not yet available... or
    # # break up the provisioning flow to spin up an initial, "core" service, then have additional utility
    # # calls to spin up RCG and roles, which then would be able to have the inline lookups (still would need
    # # the to-be reference list for RCGs, however).
    # if roles:
    #     pass

    return service


def provision_service(
    api_client: ApiClient, cluster_name: str, service: ApiService
) -> ApiService:
    service_api = ServicesResourceApi(api_client)

    provisioned_service = next(
        (
            iter(
                service_api.create_services(
                    cluster_name=cluster_name,
                    body=ApiServiceList(items=[service]),
                ).items
            )
        ),
        None,
    )

    if provisioned_service is None:
        return

    # Wait for any running commands like First Run
    available_cmds = service_api.list_service_commands(
        cluster_name=cluster_name,
        service_name=provisioned_service.name,
    )

    running_cmds = service_api.list_active_commands(
        cluster_name=cluster_name,
        service_name=provisioned_service.name,
    )

    try:
        wait_commands(api_client=api_client, commands=running_cmds)
        return provisioned_service
    except Exception as e:
        raise ServiceException(str(e))


def toggle_service_maintenance(
    api_client: ApiClient, service: ApiService, maintenance: bool, check_mode: bool
) -> bool:
    service_api = ServicesResourceApi(api_client)
    changed = False

    if maintenance and not service.maintenance_mode:
        changed = True
        cmd = service_api.enter_maintenance_mode
    elif not maintenance and service.maintenance_mode:
        changed = True
        cmd = service_api.exit_maintenance_mode

    if not check_mode and changed:
        maintenance_cmd = cmd(
            cluster_name=service.cluster_ref.cluster_name,
            service_name=service.name,
        )

        if maintenance_cmd.success is False:
            raise ServiceMaintenanceStateException(
                f"Unable to set Maintenance mode to '{maintenance}': {maintenance_cmd.result_message}"
            )

    return changed


def toggle_service_state(
    api_client: ApiClient, service: ApiService, state: str, check_mode: bool
) -> ApiServiceState:
    service_api = ServicesResourceApi(api_client)
    changed = None

    if state == "started" and service.service_state not in [ApiServiceState.STARTED]:
        changed = ApiServiceState.STARTED
        cmd = service_api.start_command
    elif state == "stopped" and service.service_state not in [
        ApiServiceState.STOPPED,
        ApiServiceState.NA,
    ]:
        changed = ApiServiceState.STOPPED
        cmd = service_api.stop_command
    elif state == "restarted":
        changed = ApiServiceState.STARTED
        cmd = service_api.restart_command

    if not check_mode and changed:
        exec_cmd = cmd(
            cluster_name=service.cluster_ref.cluster_name,
            service_name=service.name,
        )
        wait_command(api_client=api_client, command=exec_cmd)

    return changed


def read_cm_service(api_client: ApiClient) -> ApiService:
    """Read the Cloudera Manager service and its role config group and role dependents.

    Args:
        api_client (ApiClient): _description_

    Returns:
        ApiService: _description_
    """
    service_api = MgmtServiceResourceApi(api_client)
    rcg_api = MgmtRoleConfigGroupsResourceApi(api_client)
    role_api = MgmtRolesResourceApi(api_client)

    service = service_api.read_service()

    if service is not None:
        # Gather the service-wide configuration
        service.config = service_api.read_service_config()

        # Gather each role config group configuration
        service.role_config_groups = [
            rcg for rcg in rcg_api.read_role_config_groups().items if rcg.config.items
        ]

        # Gather each role configuration
        service.roles = role_api.read_roles().items
        for role in service.roles:
            role.config = role_api.read_role_config(role_name=role.name)

    return service


class ServiceConfigUpdates(object):
    def __init__(self, existing: ApiServiceConfig, updates: dict, purge: bool) -> None:
        current = {r.name: r.value for r in existing.items}
        changeset = resolve_parameter_updates(current, updates, purge)

        self.before = {
            k: current[k] if k in current else None for k in changeset.keys()
        }
        self.after = changeset

        self.diff = dict(
            before=self.before,
            after=self.after,
        )

        self.config = ApiServiceConfig(
            items=[ApiConfig(name=k, value=v) for k, v in changeset.items()]
        )

    @property
    def changed(self) -> bool:
        return bool(self.config.items)


def get_service_hosts(api_client: ApiClient, service: ApiService) -> list[ApiHost]:
    host_api = HostsResourceApi(api_client)
    seen_hosts = dict()

    for r in (
        RolesResourceApi(api_client)
        .read_roles(
            cluster_name=service.cluster_ref.cluster_name,
            service_name=service.name,
        )
        .items
    ):
        if r.host_ref.hostname not in seen_hosts:
            seen_hosts[r.host_ref.hostname] = host_api.read_host(r.host_ref.host_id)

    return seen_hosts.values()


def reconcile_service_role_config_groups(
    api_client: ApiClient,
    service: ApiService,
    role_config_groups: list[dict],
    purge: bool,
    check_mode: bool,
) -> tuple[dict, dict]:
    # Map the current role config groups by name and by base role type
    base_rcg_map, rcg_map = dict(), dict()
    for rcg in service.role_config_groups:
        if rcg.base:
            base_rcg_map[rcg.role_type] = rcg
        else:
            rcg_map[rcg.name] = rcg

    addition_list = list[ApiRoleConfigGroup]()
    diff_before, diff_after = list[dict](), list[dict]()

    rcg_api = RoleConfigGroupsResourceApi(api_client)

    for incoming_rcg in role_config_groups:
        incoming_name = incoming_rcg["name"]

        # If it's a custom role config group
        if incoming_name is not None:
            # If the custom role config group exists, update it
            current_rcg = rcg_map.pop(incoming_name, None)
            if current_rcg is not None:
                (updated_rcg, before, after) = update_role_config_group(
                    role_config_group=current_rcg,
                    display_name=incoming_rcg["display_name"],
                    config=incoming_rcg["config"],
                    purge=purge,
                )

                if before or after:
                    diff_before.append(current_rcg.to_dict())
                    diff_after.append(updated_rcg.to_dict())

                    if not check_mode:
                        rcg_api.update_role_config_group(
                            cluster_name=service.cluster_ref.cluster_name,
                            service_name=service.name,
                            role_config_group_name=current_rcg.name,
                            body=updated_rcg,
                        )

            # Else create the new custom role config group
            else:
                created_rcg = create_role_config_group(
                    api_client=api_client,
                    cluster_name=service.cluster_ref.cluster_name,
                    service_name=service.name,
                    role_type=incoming_rcg["role_type"],
                    display_name=incoming_rcg["display_name"],
                    config=incoming_rcg["config"],
                )
                diff_before.append(dict())
                diff_after.append(created_rcg.to_dict())
                addition_list(created_rcg)

        # Else it's a base role config group
        else:
            current_rcg = base_rcg_map.pop(incoming_rcg["role_type"])
            (updated_rcg, before, after) = update_role_config_group(
                role_config_group=current_rcg,
                display_name=incoming_rcg["display_name"],
                config=incoming_rcg["config"],
                purge=purge,
            )

            if before or after:
                diff_before.append(current_rcg.to_dict())
                diff_after.append(updated_rcg.to_dict())

                if not check_mode:
                    rcg_api.update_role_config_group(
                        cluster_name=service.cluster_ref.cluster_name,
                        service_name=service.name,
                        role_config_group_name=current_rcg.name,
                        body=updated_rcg,
                    )

    # Process role config group additions
    if addition_list:
        if not check_mode:
            rcg_api.create_role_config_groups(
                cluster_name=service.cluster_ref.cluster_name,
                service_name=service.name,
                body=ApiRoleConfigGroupList(items=addition_list),
            )

    # Process role config group deletions if purge is set
    if purge:
        # Reset any remaining base role config groups
        for current_rcg in base_rcg_map.values():
            (updated_rcg, before, after) = update_role_config_group(
                role_config_group=current_rcg,
                purge=purge,
            )

            if before or after:
                diff_before.append(current_rcg.to_dict())
                diff_after.append(updated_rcg.to_dict())

                if not check_mode:
                    rcg_api.update_role_config_group(
                        cluster_name=service.cluster_ref.cluster_name,
                        service_name=service.name,
                        role_config_group_name=current_rcg.name,
                        body=updated_rcg,
                    )

        # Reset to base and remove any remaining custom role config groups
        for current_rcg in rcg_map.values():
            diff_before.append(current_rcg.to_dict())
            diff_after.append(dict())

            existing_roles = rcg_api.read_roles(
                cluster_name=service.cluster_ref.cluster_name,
                service_name=service.name,
                role_config_group_name=current_rcg.name,
            ).items

            if existing_roles:
                if not check_mode:
                    rcg_api.move_roles_to_base_group(
                        cluster_name=service.cluster_ref.cluster_name,
                        service_name=service.name,
                        body=ApiRoleNameList(items=[e.name for e in existing_roles]),
                    )

            if not check_mode:
                rcg_api.delete_role_config_group(
                    cluster_name=service.cluster_ref.cluster_name,
                    service_name=service.name,
                    role_config_group_name=current_rcg.name,
                )

    return (diff_before, diff_after)
