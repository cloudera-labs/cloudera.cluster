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
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    parse_role_config_group_result,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    parse_role_result,
)

from cm_client import (
    ApiClient,
    ApiConfig,
    ApiService,
    ApiServiceConfig,
    ClustersResourceApi,
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
        for rcg in service.role_config_groups:
            rcg.config = rcg_api.read_config(
                cluster_name=cluster_name,
                service_name=service_name,
                role_config_group_name=rcg.name,
            )

        # Gather each role configuration
        for role in service.roles:
            role.config = role_api.read_role_config(
                cluster_name=cluster_name,
                service_name=service_name,
                role_name=role.name,
            )

    return service


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


def get_service_hosts(api_client: ApiClient, service: ApiService):
    return (
        ClustersResourceApi(api_client)
        .list_hosts(cluster_name=service.cluster_ref.cluster_name)
        .items
    )
