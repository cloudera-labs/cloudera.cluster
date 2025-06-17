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
A common functions for Cloudera Manager hosts
"""

from time import sleep

from cm_client import (
    ApiClient,
    ApiCluster,
    ApiConfig,
    ApiConfigList,
    ApiEntityTag,
    ApiHost,
    ApiHostRef,
    ApiHostRefList,
    ApiHostTemplate,
    ApiRole,
    ApiRoleConfigGroup,
    ApiRoleNameList,
    ApiRoleState,
    ClustersResourceApi,
    HostsResourceApi,
    HostTemplatesResourceApi,
    RolesResourceApi,
    RoleConfigGroupsResourceApi,
    RoleCommandsResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    normalize_output,
    reconcile_config_list_updates,
    wait_command,
    wait_bulk_commands,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.host_template_utils import (
    HostTemplateException,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    create_role,
    provision_service_role,
    read_role,
    read_roles,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.parcel_utils import (
    wait_parcel_staging,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    get_base_role_config_group,
)


class HostException(Exception):
    pass


class HostMaintenanceStateException(Exception):
    pass


HOST_OUTPUT = [
    "host_id",
    "ip_address",
    "hostname",
    "rack_id",
    "last_heartbeat",
    # 'role_refs': 'list[ApiRoleRef]',
    "health_summary",
    "health_checks",
    #'host_url': 'str',
    "maintenance_mode",
    "commission_state",
    "maintenance_owners",
    #'config': 'ApiConfigList',
    "num_cores",
    "num_physical_cores",
    "total_phys_mem_bytes",
    #'entity_status': 'ApiEntityStatus',
    #'cluster_ref': 'ApiClusterRef',
    "distribution",
    "tags",
]


def parse_host_result(host: ApiHost) -> dict:
    output = dict()

    # Retrieve only the cluster_name if it exists
    if host.cluster_ref is not None:
        output.update(cluster_name=host.cluster_ref.cluster_name)
    else:
        output.update(cluster_name=None)

    # Parse the host itself
    output.update(normalize_output(host.to_dict(), HOST_OUTPUT))

    # Parse the host configurations
    if host.config is not None:
        output.update(config={c.name: c.value for c in host.config.items})
    else:
        output.update(config=None)

    # Parse the role names (only the names)
    if host.role_refs is not None:
        output.update(
            roles=[r.role_name for r in host.role_refs],
        )
    else:
        output.update(roles=None)

    return output


def get_host(
    api_client: ApiClient,
    hostname: str = None,
    host_id: str = None,
    view: str = "summary",
) -> ApiHost:
    """Retrieve a Host by either hostname or host ID.

    Args:
        api_client (ApiClient): Cloudera Manager API client.
        hostname (str, optional): The cluster hostname. Defaults to None.
        host_id (str, optional): The cluster host ID. Defaults to None.

    Raises:
        ex: ApiException for all non-404 errors.

    Returns:
        ApiHost: Host object. If not found, returns None.
    """
    host_api = HostsResourceApi(api_client)
    if hostname:
        host = next(
            (h for h in host_api.read_hosts(view=view).items if h.hostname == hostname),
            None,
        )
    else:
        try:
            host = host_api.read_host(host_id=host_id, view=view)
        except ApiException as ex:
            if ex.status != 404:
                raise ex
            else:
                host = None

    if host is not None:
        host.config = host_api.read_host_config(host.host_id)

    return host


def get_host_ref(
    api_client: ApiClient, hostname: str = None, host_id: str = None
) -> ApiHostRef:
    """Retrieve a Host Reference by either hostname or host ID.

    Args:
        api_client (ApiClient): Cloudera Manager API client.
        hostname (str, optional): The cluster hostname. Defaults to None.
        host_id (str, optional): The cluster host ID. Defaults to None.

    Raises:
        ex: ApiException for all non-404 errors.

    Returns:
        ApiHostRef: Host reference object. If not found, returns None.
    """
    host = get_host(api_client, hostname, host_id)

    if host is not None:
        return ApiHostRef(host.host_id, host.hostname)
    else:
        return None


def get_host_roles(
    api_client: ApiClient,
    host: ApiHost,
) -> list[ApiRole]:
    return [
        read_role(
            api_client=api_client,
            cluster_name=role_ref.cluster_name,
            service_name=role_ref.service_name,
            role_name=role_ref.role_name,
        )
        for role_ref in host.role_refs
    ]


def create_host_model(
    api_client: ApiClient,
    hostname: str,
    ip_address: str,  # TODO Check!
    rack_id: str = None,
    config: dict = None,
    # host_template: str = None, # TODO Check!
    # roles: list[ApiRole] = None, # TODO Check!
    # role_config_groups: list[ApiRoleConfigGroup] = None, # TODO Check!
    tags: dict = None,
) -> ApiHost:
    # Set up the hostname and IP address
    host = ApiHost(hostname=hostname, ip_address=ip_address)

    # Rack ID
    if rack_id:
        host.rack_id = rack_id

    # Configuration
    if config:
        host.config = ApiConfigList(
            items=[ApiConfig(name=k, value=v) for k, v in config.items()]
        )

    # Tags
    if tags:
        host.tags = [ApiEntityTag(k, v) for k, v in tags.items()]

    return host


# Only updates, no assignment
def reconcile_host_role_configs(
    api_client: ApiClient,
    host: ApiHost,
    role_configs: list[dict],  # service, type, and config (optional)
    purge: bool,
    check_mode: bool,
    skip_redacted: bool,
    message: str = None,
) -> tuple[list[dict], list[dict]]:

    diff_before, diff_after = list[dict](), list[dict]()

    role_api = RolesResourceApi(api_client)

    for incoming_role_config in role_configs:
        # Retrieve the current role by service and type
        current_role = next(
            iter(
                read_roles(
                    api_client=api_client,
                    cluster_name=host.cluster_ref.cluster_name,
                    service_name=incoming_role_config["service"],
                    type=incoming_role_config["type"],
                    host_id=host.host_id,
                ).items
            ),
            None,
        )

        # If no existing role of service and type exists, raise an error
        if current_role is None:
            raise HostException(
                f"No role of type, '{incoming_role_config['type']}', found for service, '{incoming_role_config['service']}', on cluster, '{host.cluster_ref.cluster_name}'"
            )

        # Reconcile role override configurations
        if incoming_role_config["config"] or purge:
            incoming_config = incoming_role_config.get("config", dict())

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
                diff_before.append(dict(name=current_role.name, config=config_before))
                diff_after.append(dict(name=current_role.name, config=config_after))

                current_role.config = updated_config

                if not check_mode:
                    role_api.update_role_config(
                        cluster_name=host.cluster_ref.cluster_name,
                        service_name=current_role.service_ref.service_name,
                        role_name=current_role.name,
                        body=current_role.config,
                        message=message,
                    )

    return (diff_before, diff_after)


def reconcile_host_role_config_groups(
    api_client: ApiClient,
    cluster: ApiCluster,
    host: ApiHost,
    role_config_groups: list[dict],  # service, type (optional), name (optional)
    purge: bool,
    skip_redacted: bool,
    check_mode: bool,
) -> tuple[list[dict], list[dict]]:

    rcg_api = RoleConfigGroupsResourceApi(api_client)

    # Index by all cluster role config groups by name
    cluster_rcgs = _read_cluster_rcgs(
        api_client=api_client,
        cluster=cluster,
    )

    # Index the declared role config groups by name
    declared_rcgs = dict[str, ApiRoleConfigGroup]()  # RCG name -> RCG
    for rcg in role_config_groups:
        # If the role config group is a base, retrieve its name
        if rcg.get("name", None) is None:
            base_rcg = get_base_role_config_group(
                api_client=api_client,
                cluster_name=host.cluster_ref.cluster_name,
                service_name=rcg["service"],
                role_type=rcg["type"],
            )
            if base_rcg is None:
                raise HostException(
                    f"Base role config group for type, '{rcg['type']}', not found."
                )
            declared_rcgs[base_rcg.name] = base_rcg
        # Else, confirm the custom role config group and use its name
        else:
            custom_rcg = rcg_api.read_role_config_group(
                cluster_name=host.cluster_ref.cluster_name,
                service_name=rcg["service"],
                role_config_group_name=rcg["name"],
            )
            if custom_rcg is None:
                raise HostException(
                    f"Named role config group, '{rcg['name']}', not found."
                )
            declared_rcgs[custom_rcg.name] = custom_rcg

    # Retrieve the associated role config groups from each installed role on the host
    host_rcgs = _read_host_rcgs(
        api_client=api_client,
        host=host,
        cluster_rcgs=cluster_rcgs,
    )

    # TODO Validate if the parcel staging check is still needed
    # Read the parcel states for the cluster until all are at a stable stage
    wait_parcel_staging(
        api_client=api_client,
        cluster=cluster,
    )

    # Reconcile the role config groups on the host with the declared role config groups
    return _reconcile_host_rcgs(
        api_client=api_client,
        host=host,
        cluster_rcgs=cluster_rcgs,
        declared_rcgs=declared_rcgs,
        host_rcgs=host_rcgs,
        purge=purge,
        check_mode=check_mode,
    )


def _read_cluster_rcgs(
    api_client: ApiClient,
    cluster: ApiCluster,
) -> dict[str, ApiRoleConfigGroup]:
    service_api = ServicesResourceApi(api_client)
    rcg_api = RoleConfigGroupsResourceApi(api_client)
    return {
        rcg.name: rcg
        for service in service_api.read_services(cluster_name=cluster.name).items
        for rcg in rcg_api.read_role_config_groups(
            cluster_name=cluster.name, service_name=service.name
        ).items
    }


def _read_host_rcgs(
    api_client: ApiClient,
    host: ApiHost,
    cluster_rcgs: dict[str, ApiRoleConfigGroup],
) -> dict[str, ApiRoleConfigGroup]:
    current_rcgs = dict[str, ApiRoleConfigGroup]()
    for role_ref in host.role_refs:
        role = read_role(
            api_client=api_client,
            cluster_name=role_ref.cluster_name,
            service_name=role_ref.service_name,
            role_name=role_ref.role_name,
        )
        if role.role_config_group_ref.role_config_group_name in cluster_rcgs:
            current_rcgs[
                role.role_config_group_ref.role_config_group_name
            ] = cluster_rcgs[role.role_config_group_ref.role_config_group_name]
        else:
            raise Exception(
                f"Invalid role config group reference, '{role.role_config_group_ref.role_config_group_name}', on host, {host.hostname}"
            )
    return current_rcgs


def _reconcile_host_rcgs(
    api_client: ApiClient,
    host: ApiHost,
    cluster_rcgs: dict[str, ApiRoleConfigGroup],
    declared_rcgs: dict[str, ApiRoleConfigGroup],
    host_rcgs: dict[str, ApiRoleConfigGroup],
    purge: bool,
    check_mode: bool,
) -> tuple[list[dict], list[dict]]:

    diff_before, diff_after = list[dict](), list[dict]()

    role_api = RolesResourceApi(api_client)

    additions = set(declared_rcgs.keys()) - set(host_rcgs.keys())
    deletions = set(host_rcgs.keys()) - set(declared_rcgs.keys())

    # If the host template has additional assignments
    if additions:
        for add_rcg_name in additions:

            # Retrieve the role config group by name from the cluster
            add_rcg = cluster_rcgs[add_rcg_name]

            # Create the role instance model using the role config group
            created_role = create_role(
                api_client=api_client,
                host_id=host.host_id,
                cluster_name=add_rcg.service_ref.cluster_name,
                service_name=add_rcg.service_ref.service_name,
                role_type=add_rcg.role_type,
                role_config_group=add_rcg.name,
            )

            diff_before.append(dict())
            diff_after.append(created_role.to_dict())

            if not check_mode:
                provision_service_role(
                    api_client=api_client,
                    cluster_name=add_rcg.service_ref.cluster_name,
                    service_name=add_rcg.service_ref.service_name,
                    role=created_role,
                )

    # If the host has extraneous assignments
    if deletions and purge:
        for del_rcg_name in deletions:

            # Retrieve the current role config group by name
            del_rcg = cluster_rcgs[del_rcg_name]  # current_rcgs[del_rcg_name]

            # Retrieve the role instance on the host via the role config group's type
            del_roles = read_roles(
                api_client=api_client,
                host_id=host.host_id,
                cluster_name=del_rcg.service_ref.cluster_name,
                service_name=del_rcg.service_ref.service_name,
                type=del_rcg.role_type,
            ).items

            if not del_roles:
                raise Exception(
                    f"Error reading role type, '{del_rcg.role_type}', for service, '{del_rcg.service_ref.service_name}', on cluster, '{del_rcg.service_ref.cluster_name}'"
                )
            if len(del_roles) != 1:
                raise Exception(
                    f"Error, multiple instances for role type, '{del_rcg.role_type}', for service, '{del_rcg.service_ref.service_name}', on cluster, '{del_rcg.service_ref.cluster_name}'"
                )

            diff_before.append(del_roles[0].to_dict())
            diff_after.append(dict())

            if not check_mode:
                role_api.delete_role(
                    cluster_name=del_roles[0].service_ref.cluster_name,
                    service_name=del_roles[0].service_ref.service_name,
                    role_name=del_roles[0].name,
                )
    return (diff_before, diff_after)


def reconcile_host_template_assignments(
    api_client: ApiClient,
    cluster: ApiCluster,
    host: ApiHost,
    host_template: ApiHostTemplate,
    purge: bool,
    check_mode: bool,
) -> tuple[list[dict], list[dict]]:

    host_template_api = HostTemplatesResourceApi(api_client)

    # Index by all cluster role config groups by name
    cluster_rcg_map = _read_cluster_rcgs(
        api_client=api_client,
        cluster=cluster,
    )

    # Index the host template role config groups by name
    ht_rcgs = dict[str, ApiRoleConfigGroup]()  # RCG name -> RCG
    for rcg_ref in host_template.role_config_group_refs:
        if rcg_ref.role_config_group_name in cluster_rcg_map:
            ht_rcgs[rcg_ref.role_config_group_name] = cluster_rcg_map[
                rcg_ref.role_config_group_name
            ]
        else:
            raise HostTemplateException(
                f"Invalid role config group reference, '{rcg_ref.role_config_group_name}', in host template, {host_template.name}"
            )

    # Retrieve the associated role config groups from each installed role
    current_rcgs = _read_host_rcgs(
        api_client=api_client,
        host=host,
        cluster_rcgs=cluster_rcg_map,
    )

    # If the host has no current role assignments
    if not current_rcgs:
        diff_before, diff_after = list[dict](), list[dict]()

        for add_rcg in ht_rcgs.values():
            diff_before.append(dict())
            diff_after.append(
                create_role(
                    api_client=api_client,
                    host_id=host.host_id,
                    cluster_name=add_rcg.service_ref.cluster_name,
                    service_name=add_rcg.service_ref.service_name,
                    role_type=add_rcg.role_type,
                    role_config_group=add_rcg.name,
                ).to_dict()
            )

        if not check_mode:
            # Read the parcel states for the cluster until all are at a stable stage
            wait_parcel_staging(
                api_client=api_client,
                cluster=cluster,
            )

            # Apply the host template
            def _apply():
                apply_cmd = host_template_api.apply_host_template(
                    cluster_name=cluster.name,
                    host_template_name=host_template.name,
                    start_roles=False,
                    body=ApiHostRefList(
                        items=[ApiHostRef(host_id=host.host_id, hostname=host.hostname)]
                    ),
                )
                wait_command(
                    api_client=api_client,
                    command=apply_cmd,
                )

            retries = 3
            delay = 10
            attempts = 0
            while attempts < retries:
                try:
                    _apply()
                    break
                except ApiException as ae:
                    attempts += 1
                    if ae.status == 400:
                        sleep(delay)
                    else:
                        raise ae

        return (diff_before, diff_after)

    # Else the host has role assignments
    else:
        # Read the parcel states for the cluster until all are at a stable stage
        wait_parcel_staging(
            api_client=api_client,
            cluster=cluster,
        )

        # Reconcile the role assignments of the host template
        return _reconcile_host_rcgs(
            api_client=api_client,
            host=host,
            cluster_rcgs=cluster_rcg_map,
            declared_rcgs=ht_rcgs,
            host_rcgs=current_rcgs,
            purge=purge,
            check_mode=check_mode,
        )


def toggle_host_role_states(
    api_client: ApiClient, host: ApiHost, state: str, check_mode: bool
) -> tuple[list[dict], list[dict]]:

    service_api = ServicesResourceApi(api_client)
    role_api = RoleCommandsResourceApi(api_client)

    before_roles = list[dict]
    after_roles = list[dict]

    service_map = dict[str, list[ApiRole]]()

    # Index each role instance on the host by its service
    for role in get_host_roles(api_client, host):
        if role.service_ref.service_name in service_map:
            service_map[role.service_ref.service_name].append(role)
        else:
            service_map[role.service_ref.service_name] = [role]

    # For each service, handle the role state
    for service_name, roles in service_map.items():
        service = service_api.read_service(
            cluster_name=host.cluster_ref.cluster_name,
            service_name=service_name,
        )

        changed_roles = list()

        for role in roles:
            if state == "started" and role.role_state not in [ApiRoleState.STARTED]:
                before_roles.append(dict(name=role.name, role_state=role.role_state))
                after_roles.append(
                    dict(name=role.name, role_state=ApiRoleState.STARTED)
                )
                changed_roles.append(role)
                cmd = role_api.start_command
            elif state == "stopped" and role.role_state not in [
                ApiRoleState.STOPPED,
                ApiRoleState.NA,
            ]:
                before_roles.append(dict(name=role.name, role_state=role.role_state))
                after_roles.append(
                    dict(name=role.name, role_state=ApiRoleState.STOPPED)
                )
                changed_roles.append(role)
                cmd = role_api.stop_command
            elif state == "restarted":
                before_roles.append(dict(name=role.name, role_state=role.role_state))
                after_roles.append(
                    dict(name=role.name, role_state=ApiRoleState.STARTED)
                )
                changed_roles.append(role)
                cmd = role_api.restart_command

        if not check_mode and changed_roles:
            exec_cmds = cmd(
                cluster_name=service.cluster_ref.cluster_name,
                service_name=service.name,
                body=ApiRoleNameList(items=changed_roles),
            )
            wait_bulk_commands(api_client=api_client, commands=exec_cmds)

    return (before_roles, after_roles)


def toggle_host_maintenance(
    api_client: ApiClient,
    host: ApiHost,
    maintenance: bool,
    check_mode: bool,
) -> bool:
    host_api = HostsResourceApi(api_client)
    changed = False

    if maintenance and not host.maintenance_mode:
        changed = True
        cmd = host_api.enter_maintenance_mode
    elif not maintenance and host.maintenance_mode:
        changed = True
        cmd = host_api.exit_maintenance_mode

    if not check_mode and changed:
        maintenance_cmd = cmd(
            host_id=host.host_id,
        )

        if maintenance_cmd.success is False:
            raise HostMaintenanceStateException(
                f"Unable to set Maintenance mode to '{maintenance}': {maintenance_cmd.result_message}"
            )

    return changed


def detach_host(
    api_client: ApiClient,
    host: ApiHost,
    purge: bool,
    check_mode: bool,
) -> tuple[list[dict], list[dict]]:

    cluster_api = ClustersResourceApi(api_client)
    role_api = RolesResourceApi(api_client)

    before_role = list[dict]()
    after_role = list[dict]()

    # Get all role instances on the host
    current_roles = get_host_roles(
        api_client=api_client,
        host=host,
    )

    if current_roles and not purge:
        raise HostException(
            f"Unable to detach from cluster, '{host.cluster_ref.cluster_name}', due to existing role instances."
        )

    # Decommission the entirety of the host's roles
    for del_role in current_roles:
        before_role.append(del_role.to_dict())
        after_role.append(dict())

        if not check_mode:
            role_api.delete_role(
                cluster_name=del_role.service_ref.cluster_name,
                service_name=del_role.service_ref.service_name,
                role_name=del_role.name,
            )

    # Detach from cluster
    if not check_mode:
        cluster_api.remove_host(
            cluster_name=host.cluster_ref.cluster_name,
            host_id=host.host_id,
        )

    return (before_role, after_role)
