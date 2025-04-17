# -*- coding: utf-8 -*-
#
# Copyright 2025 Cloudera, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections.abc import Generator
from time import sleep

from cm_client import (
    ApiClient,
    ApiCluster,
    ApiCommand,
    ApiConfig,
    ApiConfigList,
    ApiHostRef,
    ApiRole,
    ApiRoleConfigGroup,
    ApiRoleConfigGroupList,
    ApiRoleList,
    ApiRoleNameList,
    ApiRoleState,
    ApiService,
    ApiServiceConfig,
    ApiServiceList,
    ApiServiceState,
    ClustersResourceApi,
    CommandsResourceApi,
    MgmtRolesResourceApi,
    MgmtRoleCommandsResourceApi,
    MgmtRoleConfigGroupsResourceApi,
    RoleConfigGroupsResourceApi,
    RolesResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    wait_command,
    wait_commands,
    resolve_parameter_updates,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.host_utils import (
    get_host_ref,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    get_mgmt_roles,
    provision_service_role,
    read_role,
    read_roles,
    toggle_role_maintenance,
    toggle_role_state,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    get_base_role_config_group,
)


class AnsibleExitJson(Exception):
    """Exception class to be raised by module.exit_json and caught by the test case"""

    def __init__(self, kwargs):
        super(AnsibleExitJson, self).__init__(
            kwargs.get("msg", "General module success")
        )
        self.__dict__.update(kwargs)


class AnsibleFailJson(Exception):
    """Exception class to be raised by module.fail_json and caught by the test case"""

    def __init__(self, kwargs):
        super(AnsibleFailJson, self).__init__(
            kwargs.get("msg", "General module failure")
        )
        self.__dict__.update(kwargs)


def wait_for_command(
    api_client: ApiClient, command: ApiCommand, polling: int = 120, delay: int = 5
):
    """Polls Cloudera Manager to wait for given Command to succeed or fail."""

    poll_count = 0
    while command.active:
        if poll_count > polling:
            raise Exception("CM command timeout")
        sleep(delay)
        poll_count += 1
        command = CommandsResourceApi(api_client).read_command(command.id)
    if not command.success:
        raise Exception(f"CM command [{command.id}] failed: {command.result_message}")


def yield_service(
    api_client: ApiClient, cluster: ApiCluster, service_name: str, service_type: str
) -> Generator[ApiService]:
    """Provisions a new cluster service as a generator.
       Use with 'yield from' to delegate within a pytest fixture.

    Args:
        api_client (ApiClient): _description_
        cluster (ApiCluster): _description_
        service_name (dict): _description_
        service_type (str): _description_

    Raises:
        Exception: _description_

    Yields:
        Generator[ApiService]: _description_
    """

    api = ServicesResourceApi(api_client)
    cluster_api = ClustersResourceApi(api_client)

    service = ApiService(
        name=service_name,
        type=service_type,
    )

    api.create_services(cluster_name=cluster.name, body=ApiServiceList(items=[service]))
    cluster_api.auto_assign_roles(cluster_name=cluster.name)

    # configure = cluster_api.auto_configure(cluster_name=target_cluster.name)
    wait_for_command(
        api_client,
        api.first_run(cluster_name=cluster.name, service_name=service_name),
    )

    yield api.read_service(cluster_name=cluster.name, service_name=service_name)

    api.delete_service(cluster_name=cluster.name, service_name=service_name)


def register_service(
    api_client: ApiClient,
    registry: list[ApiService],
    cluster: ApiCluster,
    service: ApiService,
) -> ApiService:
    service_api = ServicesResourceApi(api_client)
    cm_api = ClustersResourceApi(api_client)

    # Check the cluster hosts
    hosts = [
        h
        for i, h in enumerate(cm_api.list_hosts(cluster_name=cluster.name).items)
        if i < 3
    ]

    if len(hosts) != 3:
        raise Exception(
            "Not enough available hosts to assign service roles; the cluster must have 3 or more hosts."
        )

    # Create the service
    created_service = service_api.create_services(
        cluster_name=cluster.name, body=ApiServiceList(items=[service])
    ).items[0]

    # Record the service
    registry.append(created_service)

    # Execute first run initialization
    first_run_cmd = service_api.first_run(
        cluster_name=cluster.name,
        service_name=created_service.name,
    )
    wait_for_command(api_client, first_run_cmd)

    # Refresh the service
    created_service = service_api.read_service(
        cluster_name=cluster.name, service_name=created_service.name
    )

    # Establish the maintenance mode of the service
    if service.maintenance_mode:
        maintenance_cmd = service_api.enter_maintenance_mode(
            cluster_name=cluster.name, service_name=created_service.name
        )
        wait_for_command(api_client, maintenance_cmd)
        created_service = service_api.read_service(
            cluster_name=cluster.name, service_name=created_service.name
        )

    # Establish the state the of the service
    if service.service_state and created_service.service_state != service.service_state:
        if service.service_state == ApiServiceState.STOPPED:
            stop_cmd = service_api.stop_command(
                cluster_name=cluster.name,
                service_name=created_service.name,
            )
            wait_for_command(api_client, stop_cmd)
            created_service = service_api.read_service(
                cluster_name=cluster.name, service_name=created_service.name
            )
        else:
            raise Exception(
                "Unsupported service state for fixture: " + service.service_state
            )

    # Return the provisioned service
    return created_service


def deregister_service(api_client: ApiClient, registry: list[ApiService]) -> None:
    service_api = ServicesResourceApi(api_client)

    # Delete the services
    for s in registry:
        try:
            # Check for running commands and wait for them to finish
            active_cmds = service_api.list_active_commands(
                cluster_name=s.cluster_ref.cluster_name,
                service_name=s.name,
            )

            wait_commands(
                api_client=api_client,
                commands=active_cmds,
            )

            # If the service is running, stop it
            current = service_api.read_service(
                cluster_name=s.cluster_ref.cluster_name,
                service_name=s.name,
            )

            if current.service_state == ApiServiceState.STARTED:
                stop_cmd = service_api.stop_command(
                    cluster_name=s.cluster_ref.cluster_name,
                    service_name=s.name,
                )

                wait_command(
                    api_client=api_client,
                    command=stop_cmd,
                )

            # Delete the service
            service_api.delete_service(
                cluster_name=s.cluster_ref.cluster_name,
                service_name=s.name,
            )
        except ApiException as e:
            if e.status != 404:
                raise e


def register_role(
    api_client: ApiClient, registry: list[ApiRole], service: ApiService, role: ApiRole
) -> ApiRole:
    # Create the role
    created_role = provision_service_role(
        api_client=api_client,
        cluster_name=service.cluster_ref.cluster_name,
        service_name=service.name,
        role=role,
    )

    # Record the role
    registry.append(created_role)

    # Establish the maintenance mode of the role
    toggle_role_maintenance(
        api_client=api_client,
        role=created_role,
        maintenance=role.maintenance_mode,
        check_mode=False,
    )

    # Establish the state the of the role
    toggle_role_state(
        api_client=api_client,
        role=created_role,
        state="stopped" if role.role_state == ApiRoleState.STOPPED else "started",
        check_mode=False,
    )

    # Return the provisioned role
    return created_role


def deregister_role(api_client: ApiClient, registry: list[ApiRole]) -> None:
    role_api = RolesResourceApi(api_client)

    # Delete the roles
    for r in registry:
        # Refresh the role state (and check for existence)
        try:
            refreshed_role = read_role(
                api_client=api_client,
                cluster_name=r.service_ref.cluster_name,
                service_name=r.service_ref.service_name,
                role_name=r.name,
            )

            toggle_role_state(
                api_client=api_client,
                role=refreshed_role,
                state="stopped",
                check_mode=False,
            )

            role_api.delete_role(
                cluster_name=refreshed_role.service_ref.cluster_name,
                service_name=refreshed_role.service_ref.service_name,
                role_name=refreshed_role.name,
            )
        except ApiException as e:
            if e.status != 404:
                raise e


def register_role_config_group(
    api_client: ApiClient,
    registry: list[ApiRoleConfigGroup],
    service: ApiService,
    role_config_group: ApiRoleConfigGroup,
    message: str,
) -> ApiRoleConfigGroup:
    rcg_api = RoleConfigGroupsResourceApi(api_client)

    # If creating a custom Role Config Group
    if role_config_group.name is not None:
        # Create the Role Config Group
        created_rcg = rcg_api.create_role_config_groups(
            cluster_name=service.cluster_ref.cluster_name,
            service_name=service.name,
            body=ApiRoleConfigGroupList(items=[role_config_group]),
        ).items[0]

        # Record the Role Config Group
        registry.append(created_rcg)

        # Return the Role Config Group
        return created_rcg

    # Else modify the base Role Config Group
    else:
        # Look up the base
        base_rcg = get_base_role_config_group(
            api_client=api_client,
            cluster_name=service.cluster_ref.cluster_name,
            service_name=service.name,
            role_type=role_config_group.role_type,
        )

        # Retrieve its current configuration
        base_rcg.config = rcg_api.read_config(
            cluster_name=service.cluster_ref.cluster_name,
            service_name=service.name,
            role_config_group_name=base_rcg.name,
        )

        # Record the state of the current base
        registry.append(base_rcg)

        # Add the existing base name to the incoming changes
        role_config_group.name = base_rcg.name

        # Update the configuration
        updated_base_rcg = rcg_api.update_role_config_group(
            cluster_name=service.cluster_ref.cluster_name,
            service_name=service.name,
            role_config_group_name=base_rcg.name,  # Use the base RCG's name
            message=f"{message}::set",
            body=role_config_group,
        )

        # Return the updated base Role Config Group
        return updated_base_rcg


def deregister_role_config_group(
    api_client: ApiClient, registry: list[ApiRoleConfigGroup], message: str
) -> None:
    rcg_api = RoleConfigGroupsResourceApi(api_client)
    for rcg in registry:
        # Delete the custom role config groups
        if not rcg.base:
            # The role might already be deleted, so ignore if not found
            try:
                existing_roles = rcg_api.read_roles(
                    cluster_name=rcg.service_ref.cluster_name,
                    service_name=rcg.service_ref.service_name,
                    role_config_group_name=rcg.name,
                ).items

                if existing_roles:
                    rcg_api.move_roles_to_base_group(
                        cluster_name=rcg.service_ref.cluster_name,
                        service_name=rcg.service_ref.service_name,
                        body=ApiRoleNameList([r.name for r in existing_roles]),
                    )

                rcg_api.delete_role_config_group(
                    cluster_name=rcg.service_ref.cluster_name,
                    service_name=rcg.service_ref.service_name,
                    role_config_group_name=rcg.name,
                )
            except ApiException as ex:
                if ex.status != 404:
                    raise ex

        # Reset the base Role Config Groups
        else:
            # Read the current base
            current_rcg = rcg_api.read_role_config_group(
                cluster_name=rcg.service_ref.cluster_name,
                service_name=rcg.service_ref.service_name,
                role_config_group_name=rcg.name,
            )

            # Revert the changes
            config_revert = resolve_parameter_updates(
                {c.name: c.value for c in current_rcg.config.items},
                {c.name: c.value for c in rcg.config.items},
                True,
            )

            if config_revert:
                rcg.config = ApiConfigList(
                    items=[ApiConfig(name=k, value=v) for k, v in config_revert.items()]
                )

                rcg_api.update_role_config_group(
                    cluster_name=rcg.service_ref.cluster_name,
                    service_name=rcg.service_ref.service_name,
                    role_config_group_name=rcg.name,
                    message=f"{message}::reset",
                    body=rcg,
                )


def service_wide_config(
    api_client: ApiClient, service: ApiService, params: dict, message: str
) -> Generator[ApiService]:
    """Update a service-wide configuration for a given service. Yields the
       service, resetting the configuration to its prior state. Use with
       'yield from' within a pytest fixture.

    Args:
        api_client (ApiClient): _description_
        service (ApiService): _description_
        params (dict): _description_
        message (str): _description_

    Raises:
        Exception: _description_

    Yields:
        Generator[ApiService]: _description_
    """
    service_api = ServicesResourceApi(api_client)

    # Retrieve all of the pre-setup configurations
    pre = service_api.read_service_config(
        cluster_name=service.cluster_ref.cluster_name,
        service_name=service.name,
    )

    # Set the test configurations
    # Do so serially, since a failed update due to defaults (see ApiException) will cause remaining
    # configuration entries to not run. Long-term solution is to check-and-set, which is
    # what the Ansible modules do...
    for k, v in params.items():
        try:
            service_api.update_service_config(
                cluster_name=service.cluster_ref.cluster_name,
                service_name=service.name,
                message=f"{message}::set",
                body=ApiServiceConfig(items=[ApiConfig(name=k, value=v)]),
            )
        except ApiException as ae:
            if ae.status != 400 or "delete with template" not in str(ae.body):
                raise Exception(str(ae))

    # Yield the targeted service
    yield service

    # Retrieve all of the post-setup configurations
    post = service_api.read_service_config(
        cluster_name=service.cluster_ref.cluster_name,
        service_name=service.name,
    )

    # Reconcile the configurations
    pre_set = set([c.name for c in pre.items])

    reconciled = pre.items.copy()
    reconciled.extend(
        [
            ApiConfig(name=k.name, value=None)
            for k in post.items
            if k.name not in pre_set
        ]
    )

    service_api.update_service_config(
        cluster_name=service.cluster_ref.cluster_name,
        service_name=service.name,
        message=f"{message}::reset",
        body=ApiServiceConfig(items=reconciled),
    )


def provision_cm_role(
    api_client: ApiClient, role_name: str, role_type: str, host_id: str
) -> Generator[ApiRole]:
    """Yield a newly-created Cloudera Manager Service role, deleting the
       role after use. Use with 'yield from' within a pytest fixture.

    Args:
        api_client (ApiClient): _description_
        role_name (str): _description_
        role_type (str): _description_
        host_id (str): _description_

    Yields:
        Generator[ApiRole]: _description_
    """
    api = MgmtRolesResourceApi(api_client)

    role = ApiRole(
        name=role_name,
        type=role_type,
        host_ref=ApiHostRef(host_id=host_id),
    )

    provisioned_role = next(
        iter(api.create_roles(body=ApiRoleList(items=[role])).items), None
    )

    yield provisioned_role

    try:
        api.delete_role(role_name=provisioned_role.name)
    except ApiException as ae:
        if ae.status != 404:
            raise ae


def set_cm_role(
    api_client: ApiClient, cluster: ApiCluster, role: ApiRole
) -> Generator[ApiRole]:
    """Set a net-new Cloudera Manager Service role. Yields the new role,
    resetting to any existing role upon completion. Use with 'yield from'
    within a pytest fixture.
    """
    role_api = MgmtRolesResourceApi(api_client)
    role_cmd_api = MgmtRoleCommandsResourceApi(api_client)

    # Check for existing management role
    pre_role = next(
        iter([r for r in get_mgmt_roles(api_client, role.type).items]), None
    )

    if pre_role is not None:
        # Get the current state
        pre_role.config = role_api.read_role_config(role_name=pre_role.name)

        # Remove the prior role
        role_api.delete_role(role_name=pre_role.name)

    if not role.host_ref:
        cluster_api = ClustersResourceApi(api_client)

        # Get first host of the cluster
        hosts = cluster_api.list_hosts(cluster_name=cluster.name)

        if not hosts.items:
            raise Exception(
                "No available hosts to assign the Cloudera Manager Service role."
            )

        role.host_ref = get_host_ref(api_client, host_id=hosts.items[0].host_id)

    # Create the role under test
    current_role = next(
        iter(role_api.create_roles(body=ApiRoleList(items=[role])).items), None
    )
    current_role.config = role_api.read_role_config(role_name=current_role.name)

    if role.maintenance_mode:
        role_api.enter_maintenance_mode(role_name=current_role.name)

    if role.role_state in [ApiRoleState.STARTING, ApiRoleState.STARTED]:
        start_cmds = role_cmd_api.start_command(
            body=ApiRoleNameList(items=[current_role.name])
        )
        if start_cmds.errors:
            error_msg = "\n".join(start_cmds.errors)
            raise Exception(error_msg)

        for cmd in start_cmds.items:
            # Serial monitoring
            wait_for_command(api_client=api_client, command=cmd)

    # Yield the role under test
    yield current_role

    # Remove the role under test
    current_role = role_api.delete_role(role_name=current_role.name)

    # Reinstate the previous role
    if pre_role is not None:
        role_api.create_roles(body=ApiRoleList(items=[pre_role]))
        if pre_role.maintenance_mode:
            role_api.enter_maintenance_mode(pre_role.name)
        if pre_role.role_state in [ApiRoleState.STARTED, ApiRoleState.STARTING]:
            restart_cmds = role_cmd_api.restart_command(
                body=ApiRoleNameList(items=[pre_role.name])
            )
            if restart_cmds.errors:
                error_msg = "\n".join(restart_cmds.errors)
                raise Exception(error_msg)

            for cmd in restart_cmds.items:
                # Serial monitoring
                wait_for_command(api_client=api_client, command=cmd)


def set_cm_role_config(
    api_client: ApiClient, role: ApiRole, params: dict, message: str
) -> Generator[ApiRole]:
    """Update a role configuration for a given role. Yields the
       role, resetting the configuration to its prior state. Use with
       'yield from' within a pytest fixture.

    Args:
        api_client (ApiClient): _description_
        role (ApiRole): _description_
        params (dict): _description_
        message (str): _description_

    Raises:
        Exception: _description_

    Yields:
        Generator[ApiRole]: _description_
    """
    role_api = MgmtRolesResourceApi(api_client)

    # Retrieve all of the pre-setup configurations
    pre = role_api.read_role_config(role.name)

    # Set the test configurations
    # Do so serially, since a failed update due to defaults (see ApiException) will cause remaining
    # configuration entries to not run. Long-term solution is to check-and-set, which is
    # what the Ansible modules do...
    for k, v in params.items():
        try:
            role_api.update_role_config(
                role_name=role.name,
                message=f"{message}::set",
                body=ApiConfigList(items=[ApiConfig(name=k, value=v)]),
            )
        except ApiException as ae:
            if ae.status != 400 or "delete with template" not in str(ae.body):
                raise Exception(str(ae))

    # Yield the targeted role
    yield role_api.read_role(role_name=role.name)

    # Retrieve all of the post-setup configurations
    post = role_api.read_role_config(role_name=role.name)

    # Reconcile the configurations
    pre_set = set([c.name for c in pre.items])

    reconciled = pre.items.copy()
    reconciled.extend(
        [
            ApiConfig(name=k.name, value=None)
            for k in post.items
            if k.name not in pre_set
        ]
    )

    role_api.update_role_config(
        role_name=role.name,
        message=f"{message}::reset",
        body=ApiConfigList(items=reconciled),
    )


def set_cm_role_config_group(
    api_client: ApiClient,
    role_config_group: ApiRoleConfigGroup,
    update: ApiRoleConfigGroup,
    message: str,
) -> Generator[ApiRoleConfigGroup]:
    """Update a configuration for a given Cloudera Manager Service role config group.
       Yields the role config group and upon returning control, will reset the
       configuration to its prior state.
       Use with 'yield from' within a pytest fixture.

    Args:
        api_client (ApiClient): CM API client
        role_config_group (ApiRoleConfigGroup): The Role Config Group to manage
        update (ApiRoleConfigGroup): The state to set
        message (str): Transaction descriptor; will be appended with '::[re]set'

    Yields:
        Generator[ApiRoleConfigGroup]: The updated Role Config Group
    """
    rcg_api = MgmtRoleConfigGroupsResourceApi(api_client)

    # Ensure the modification (not a replacement) of the existing role config group
    update.name = role_config_group.name

    # Update the role config group
    pre_rcg = rcg_api.update_role_config_group(
        role_config_group.name, message=f"{message}::set", body=update
    )

    yield pre_rcg

    # Reread the role config group
    post_rcg = rcg_api.read_role_config_group(role_config_group_name=pre_rcg.name)

    # Revert the changes
    config_revert = resolve_parameter_updates(
        {c.name: c.value for c in post_rcg.config.items},
        {c.name: c.value for c in role_config_group.config.items},
        True,
    )

    if config_revert:
        role_config_group.config = ApiConfigList(
            items=[ApiConfig(name=k, value=v) for k, v in config_revert.items()]
        )

        rcg_api.update_role_config_group(
            role_config_group.name, message=f"{message}::reset", body=role_config_group
        )


def set_role_config_group(
    api_client: ApiClient,
    cluster_name: str,
    service_name: str,
    role_config_group: ApiRoleConfigGroup,
    update: ApiRoleConfigGroup,
    message: str,
) -> Generator[ApiRoleConfigGroup]:
    """Update a configuration for a given service role config group.
       Yields the role config group and upon returning control, will reset the
       configuration to its prior state.
       Use with 'yield from' within a pytest fixture.

    Args:
        api_client (ApiClient): CM API client
        cluster_name (str): Name of the cluster
        service_name (str): Name of the service
        role_config_group (ApiRoleConfigGroup): The Role Config Group to manage
        update (ApiRoleConfigGroup): The state to set
        message (str): Transaction descriptor; will be appended with '::[re]set'

    Yields:
        Generator[ApiRoleConfigGroup]: The updated Role Config Group
    """
    rcg_api = RoleConfigGroupsResourceApi(api_client)

    # Ensure the modification (not a replacement) of the existing role config group
    update.name = role_config_group.name

    # Update the role config group
    pre_rcg = rcg_api.update_role_config_group(
        cluster_name=cluster_name,
        service_name=service_name,
        role_config_group_name=role_config_group.name,
        message=f"{message}::set",
        body=update,
    )

    yield pre_rcg

    # Reread the role config group
    post_rcg = rcg_api.read_role_config_group(
        cluster_name=cluster_name,
        service_name=service_name,
        role_config_group_name=pre_rcg.name,
    )

    # Revert the changes
    config_revert = resolve_parameter_updates(
        {c.name: c.value for c in post_rcg.config.items},
        {c.name: c.value for c in role_config_group.config.items},
        True,
    )

    if config_revert:
        role_config_group.config = ApiConfigList(
            items=[ApiConfig(name=k, value=v) for k, v in config_revert.items()]
        )

        rcg_api.update_role_config_group(
            cluster_name=cluster_name,
            service_name=service_name,
            role_config_group_name=role_config_group.name,
            message=f"{message}::reset",
            body=role_config_group,
        )


def read_expected_roles(
    api_client: ApiClient, cluster_name: str, service_name: str
) -> list[ApiRole]:
    return (
        RolesResourceApi(api_client)
        .read_roles(
            cluster_name=cluster_name,
            service_name=service_name,
        )
        .items
    )
