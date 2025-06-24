# -*- coding: utf-8 -*-

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
    reconcile_config_list_updates,
    resolve_parameter_changeset,
    wait_command,
    wait_commands,
    TagUpdates,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    create_role_config_group,
    get_base_role_config_group,
    parse_role_config_group_result,
    update_role_config_group,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    create_role,
    read_roles,
    read_roles_by_type,
    parse_role_result,
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
    ApiRoleList,
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
        parsed_rcgs = [
            parse_role_config_group_result(rcg) for rcg in service.role_config_groups
        ]
        output.update(
            # Remove service_name from output
            role_config_groups=[
                {k: v for k, v in rcg_dict.items() if k != "service_name"}
                for rcg_dict in parsed_rcgs
            ],
        )

    # Parse the roles via util function
    if service.roles is not None:
        parsed_roles = [parse_role_result(r) for r in service.roles]
        output.update(
            # Remove service_name from output
            roles=[
                {k: v for k, v in role_dict.items() if k != "service_name"}
                for role_dict in parsed_roles
            ],
        )

    return output


def read_service(
    api_client: ApiClient,
    cluster_name: str,
    service_name: str,
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

    service = service_api.read_service(
        cluster_name=cluster_name,
        service_name=service_name,
    )

    if service is not None:
        # Gather the service-wide configuration
        service.config = service_api.read_service_config(
            cluster_name=cluster_name,
            service_name=service_name,
        )

        # Gather each role config group configuration
        service.role_config_groups = rcg_api.read_role_config_groups(
            cluster_name=cluster_name,
            service_name=service_name,
        ).items

        # Gather each role and its config
        service.roles = read_roles(
            api_client=api_client,
            cluster_name=cluster_name,
            service_name=service_name,
        ).items

    return service


def read_services(api_client: ApiClient, cluster_name: str) -> list[ApiService]:
    """Read the cluster services and gather each services' role config group and role dependents.

    Args:
        api_client (ApiClient): _description_
        cluster_name (str): _description_

    Returns:
        ApiService: _description_
    """
    service_api = ServicesResourceApi(api_client)
    rcg_api = RoleConfigGroupsResourceApi(api_client)

    services = list[ApiService]()

    discovered_services = service_api.read_services(
        cluster_name=cluster_name,
    ).items

    for service in discovered_services:
        # Gather the service-wide configuration
        service.config = service_api.read_service_config(
            cluster_name=cluster_name,
            service_name=service.name,
        )

        # Gather each role config group configuration
        service.role_config_groups = rcg_api.read_role_config_groups(
            cluster_name=cluster_name,
            service_name=service.name,
        ).items

        # Gather each role and its config
        service.roles = read_roles(
            api_client=api_client,
            cluster_name=cluster_name,
            service_name=service.name,
        ).items

        # Add it to the output
        services.append(service)

    return services


def create_service_model(
    api_client: ApiClient,
    name: str,
    type: str,
    cluster_name: str,
    display_name: str = None,
    config: dict = None,
    tags: dict = None,
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
            f"Invalid service type '{type}' for cluster '{cluster_name}'",
        )

    # Set up the service basics
    service = ApiService(name=name, type=str(type).upper())

    if display_name:
        service.display_name = display_name

    # Service-wide configurations
    if config:
        service.config = ApiConfigList(
            items=[ApiConfig(name=k, value=v) for k, v in config.items()],
        )

    # Tags
    if tags:
        service.tags = [ApiEntityTag(k, v) for k, v in tags.items()]

    return service


def provision_service(
    api_client: ApiClient,
    cluster_name: str,
    service: ApiService,
) -> ApiService:
    service_api = ServicesResourceApi(api_client)

    provisioned_service = next(
        (
            iter(
                service_api.create_services(
                    cluster_name=cluster_name,
                    body=ApiServiceList(items=[service]),
                ).items,
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
    api_client: ApiClient,
    service: ApiService,
    maintenance: bool,
    check_mode: bool,
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
                f"Unable to set Maintenance mode to '{maintenance}': {maintenance_cmd.result_message}",
            )

    return changed


def toggle_service_state(
    api_client: ApiClient,
    service: ApiService,
    state: str,
    check_mode: bool,
) -> ApiServiceState:
    service_api = ServicesResourceApi(api_client)
    changed = None

    if state == "started" and service.service_state not in [ApiServiceState.STARTED]:
        changed = ApiServiceState.STARTED

        if service.service_state == ApiServiceState.NA:
            cmd = service_api.first_run
        else:
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


def reconcile_service_config(
    api_client: ApiClient,
    service: ApiService,
    config: dict,
    purge: bool,
    check_mode: bool,
    skip_redacted: bool,
    message: str,
) -> tuple[dict, dict]:
    service_api = ServicesResourceApi(api_client)

    def _handle_config(
        existing: ApiServiceConfig,
    ) -> tuple[ApiServiceConfig, dict, dict]:
        current = {r.name: r.value for r in existing.items}
        changeset = resolve_parameter_changeset(current, config, purge, skip_redacted)

        before = {k: current[k] if k in current else None for k in changeset.keys()}
        after = changeset

        reconciled_config = ApiServiceConfig(
            items=[ApiConfig(name=k, value=v) for k, v in changeset.items()],
        )

        return (reconciled_config, before, after)

    initial_before = dict()
    initial_after = dict()
    retry = 0

    while retry < 3:
        existing_config = service_api.read_service_config(
            cluster_name=service.cluster_ref.cluster_name,
            service_name=service.name,
        )

        (updated_config, before, after) = _handle_config(existing_config)

        if (before or after) and not check_mode:
            if retry == 0:
                initial_before, initial_after = before, after

            service_api.update_service_config(
                cluster_name=service.cluster_ref.cluster_name,
                service_name=service.name,
                message=message,
                body=updated_config,
            )

            config_check = service_api.read_service_config(
                cluster_name=service.cluster_ref.cluster_name,
                service_name=service.name,
            )

            (_, checked_before, checked_after) = _handle_config(config_check)

            if not checked_before or not checked_after:
                return (initial_before, initial_after)
            else:
                retry += 1
        else:
            return (before, after)

    raise ServiceException(
        f"Unable to reconcile service-wide configuration for '{service.name}' in cluster '{service.cluster_ref.cluster_name}",
        before,
        after,
    )


class ServiceConfigUpdates(object):
    def __init__(self, existing: ApiServiceConfig, updates: dict, purge: bool) -> None:
        current = {r.name: r.value for r in existing.items}
        changeset = resolve_parameter_changeset(current, updates, purge)

        self.before = {
            k: current[k] if k in current else None for k in changeset.keys()
        }
        self.after = changeset

        self.diff = dict(
            before=self.before,
            after=self.after,
        )

        self.config = ApiServiceConfig(
            items=[ApiConfig(name=k, value=v) for k, v in changeset.items()],
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
    skip_redacted: bool,
    message: str,
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
                    skip_redacted=skip_redacted,
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
                            message=message,
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
                skip_redacted=skip_redacted,
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
                        message=message,
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
                skip_redacted=skip_redacted,
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
                        message=message,
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


def reconcile_service_roles(
    api_client: ApiClient,
    service: ApiService,
    roles: list[dict],
    purge: bool,
    check_mode: bool,
    skip_redacted: bool,
    message: str,
    # maintenance: bool,
    # state: str,
) -> tuple[dict, dict]:

    diff_before, diff_after = list[dict](), list[dict]()

    role_api = RolesResourceApi(api_client)
    rcg_api = RoleConfigGroupsResourceApi(api_client)

    for incoming_role in roles:
        # Prepare for any per-entry changes
        role_entry_before, role_entry_after = list(), list()

        # Prepare list for any new role instances
        addition_list = list[ApiRole]()

        # Get all existing instances of type per host
        current_role_instances = read_roles_by_type(
            api_client=api_client,
            cluster_name=service.cluster_ref.cluster_name,
            service_name=service.name,
            role_type=incoming_role["type"],
        ).items

        # Get the base role config group for the type
        base_rcg = get_base_role_config_group(
            api_client=api_client,
            cluster_name=service.cluster_ref.cluster_name,
            service_name=service.name,
            role_type=incoming_role["type"],
        )

        # Get the role config group, if defined, for use with all of the instance associations
        if incoming_role.get("role_config_group", None) is not None:
            incoming_rcg = rcg_api.read_role_config_group(
                cluster_name=service.cluster_ref.cluster_name,
                service_name=service.name,
                role_config_group_name=incoming_role.get("role_config_group"),
            )
        else:
            incoming_rcg = None

        # Index the current role instances by hostname
        instance_map = {r.host_ref.hostname: r for r in current_role_instances}

        # Reconcile existence of type/host
        for h in incoming_role["hostnames"]:
            # Prepare any role instance changes
            instance_role_before, instance_role_after = dict(), dict()

            # Create new role - config, rcg, tags, and host
            if h not in instance_map:
                created_role = create_role(
                    api_client=api_client,
                    cluster_name=service.cluster_ref.cluster_name,
                    service_name=service.name,
                    role_type=incoming_role["type"],
                    hostname=h,
                    config=incoming_role.get("config", None),
                    role_config_group=incoming_role.get("role_config_group", None),
                    tags=incoming_role.get("tags", None),
                )

                # before is already an empty dict
                instance_role_after = created_role.to_dict()

                addition_list.append(created_role)

            # Update existing role - config, tags, role config group
            else:
                current_role = instance_map.pop(h, None)
                if current_role is not None:
                    # Reconcile role override configurations
                    incoming_config = incoming_role.get("config", None)
                    if incoming_config or purge:
                        if incoming_config is None:
                            incoming_config = dict()

                        (
                            updated_config,
                            config_before,
                            config_after,
                        ) = reconcile_config_list_updates(
                            current_role.config,
                            incoming_config,
                            purge,
                            skip_redacted,
                        )

                        if config_before or config_after:
                            instance_role_before.update(config=config_before)
                            instance_role_after.update(config=config_after)

                            current_role.config = updated_config

                        if not check_mode:
                            role_api.update_role_config(
                                cluster_name=service.cluster_ref.cluster_name,
                                service_name=service.name,
                                role_name=current_role.name,
                                body=current_role.config,
                                message=message,
                            )

                    # Reconcile role tags
                    incoming_tags = incoming_role.get("tags", None)
                    if incoming_tags or purge:
                        if incoming_tags is None:
                            incoming_tags = dict()

                        tag_updates = TagUpdates(
                            current_role.tags,
                            incoming_tags,
                            purge,
                        )

                        if tag_updates.changed:
                            instance_role_before.update(tags=tag_updates.deletions)
                            instance_role_after.update(tags=tag_updates.additions)

                            if tag_updates.deletions:
                                if not check_mode:
                                    role_api.delete_tags(
                                        cluster_name=service.cluster_ref.cluster_name,
                                        service_name=service.name,
                                        role_name=current_role.name,
                                        body=tag_updates.deletions,
                                    )

                            if tag_updates.additions:
                                if not check_mode:
                                    role_api.add_tags(
                                        cluster_name=service.cluster_ref.cluster_name,
                                        service_name=service.name,
                                        role_name=current_role.name,
                                        body=tag_updates.additions,
                                    )

                    # Handle role config group associations
                    # If role config group is not present and the existing reference is not the base, reset to base
                    if (
                        incoming_rcg is None
                        and current_role.role_config_group_ref.role_config_group_name
                        != base_rcg.name
                    ):
                        instance_role_before.update(
                            role_config_group=current_role.role_config_group_ref.role_config_group_name,
                        )
                        instance_role_after.update(role_config_group=base_rcg.name)

                        if not check_mode:
                            rcg_api.move_roles_to_base_group(
                                cluster_name=service.cluster_ref.cluster_name,
                                service_name=service.name,
                                body=ApiRoleNameList(items=[current_role.name]),
                            )
                    # Else if the role config group does not match the declared
                    elif (
                        incoming_rcg is not None
                        and incoming_rcg.name
                        != current_role.role_config_group_ref.role_config_group_name
                    ):
                        instance_role_before.update(
                            role_config_group=current_role.role_config_group_ref.role_config_group_name,
                        )
                        instance_role_after.update(role_config_group=incoming_rcg.name)

                        if not check_mode:
                            rcg_api.move_roles(
                                cluster_name=service.cluster_ref.cluster_name,
                                service_name=service.name,
                                role_config_group_name=incoming_rcg.name,
                                body=ApiRoleNameList(items=[current_role.name]),
                            )

            # Record any deltas for the role entry
            if instance_role_before or instance_role_after:
                role_entry_before.append(instance_role_before)
                role_entry_after.append(instance_role_after)

        # Process role instance additions
        if addition_list:
            if not check_mode:
                role_api.create_roles(
                    cluster_name=service.cluster_ref.cluster_name,
                    service_name=service.name,
                    body=ApiRoleList(items=addition_list),
                )

        # Process role deletions if purge is set
        if purge:
            for deleted_role in instance_map.values():
                role_entry_before.append(deleted_role.to_dict())
                role_entry_after.append(dict())

                if not check_mode:
                    role_api.delete_role(
                        cluster_name=service.cluster_ref.cluster_name,
                        service_name=service.name,
                        role_name=deleted_role.name,
                    )

        # Add any changes for the role entry
        if role_entry_before or role_entry_after:
            diff_before.append(role_entry_before)
            diff_after.append(role_entry_after)

    return (diff_before, diff_after)
