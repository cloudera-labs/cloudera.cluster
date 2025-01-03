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
    ApiRole,
    ApiRoleConfigGroup,
    ApiRoleList,
    ApiRoleNameList,
    ApiRoleState,
    ApiService,
    ApiServiceConfig,
    ApiServiceList,
    ClustersResourceApi,
    CommandsResourceApi,
    MgmtRolesResourceApi,
    MgmtRoleCommandsResourceApi,
    MgmtRoleConfigGroupsResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.module_utils.host_utils import (
    get_host_ref,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    get_mgmt_roles,
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


def provision_service(
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
        host_ref=dict(hostId=host_id),
    )

    yield next(iter(api.create_roles(body=ApiRoleList(items=[role])).items), None)

    api.delete_role(role_name=role_name)


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

    pre = rcg_api.read_role_config_group(role_config_group.name)

    yield rcg_api.update_role_config_group(
        role_config_group.name, message=f"{message}::set", body=update
    )

    rcg_api.update_role_config_group(
        role_config_group.name, message=f"{message}::reset", body=pre
    )
