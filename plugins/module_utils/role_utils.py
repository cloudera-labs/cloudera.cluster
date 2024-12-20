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

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    normalize_output,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.host_utils import (
    get_host_ref,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    get_role_config_group,
)

from cm_client import (
    ApiClient,
    ApiConfig,
    ApiConfigList,
    ApiRoleList,
    ApiRoleConfigGroupRef,
    RolesResourceApi,
    MgmtRolesResourceApi,
)
from cm_client import ApiRole

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
    # Retrieve only the host_id, role_config_group, and service identifiers
    output = dict(
        host_id=role.host_ref.host_id,
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


def get_roles(
    api_client: ApiClient, cluster_name: str, service_name: str, role_type: str
) -> ApiRoleList:
    role_api = RolesResourceApi(api_client)
    return ApiRoleList(
        items=[
            r
            for r in role_api.read_roles(cluster_name, service_name).items
            if r.type == role_type
        ]
    )


class RoleHostNotFoundException(Exception):
    pass


def create_role(
    api_client: ApiClient,
    role_type: str,
    hostname: str,
    host_id: str,
    name: str = None,
    config: dict = None,
    cluster_name: str = None,
    service_name: str = None,
    role_config_group: str = None,
) -> ApiRole:
    # Set up the role
    role = ApiRole(type=str(role_type).upper())

    # Name
    if name:
        role.name = name  # No name allows auto-generation

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
        role.role_config_group_ref = ApiRoleConfigGroupRef(
            get_role_config_group(
                api_client, cluster_name, service_name, role_config_group
            ).name
        )

    # Role override configurations
    if config:
        role.config = ApiConfigList(
            items=[ApiConfig(name=k, value=v) for k, v in config.items()]
        )

    return role
