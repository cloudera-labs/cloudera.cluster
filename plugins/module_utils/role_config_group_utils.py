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

from cm_client import (
    ApiClient,
    ApiRoleConfigGroup,
    RoleConfigGroupsResourceApi,
    MgmtRoleConfigGroupsResourceApi,
)

ROLE_CONFIG_GROUP = [
    "name",
    "role_type",
    "base",
    "display_name",
    # "service_ref",
]


class BaseRoleConfigGroupDiscoveryException(Exception):
    pass


class RoleConfigGroupDiscoveryException(Exception):
    pass


def parse_role_config_group_result(role_config_group: ApiRoleConfigGroup) -> dict:
    """Parse a Role Config Group into a normalized dictionary.

    Returns the following:
    - name (str)
    - role_type (str)
    - base (bool)
    - display_name (str)
    - config (dict)

    Args:
        role_config_group (ApiRoleConfigGroup): Role Config Group

    Returns:
        dict: Normalized dictionary of returned values
    """
    # Retrieve only the service identifier
    output = dict(service_name=role_config_group.service_ref.service_name)
    output.update(normalize_output(role_config_group.to_dict(), ROLE_CONFIG_GROUP))
    output.update(config={c.name: c.value for c in role_config_group.config.items})
    return output


def get_base_role_config_group(
    api_client: ApiClient, cluster_name: str, service_name: str, role_type: str
) -> ApiRoleConfigGroup:
    rcg_api = RoleConfigGroupsResourceApi(api_client)
    rcgs = [
        r
        for r in rcg_api.read_role_config_groups(cluster_name, service_name).items
        if r.role_type == role_type and r.base
    ]
    if len(rcgs) != 1:
        raise BaseRoleConfigGroupDiscoveryException(role_count=len(rcgs))
    else:
        return rcgs[0]


def get_mgmt_base_role_config_group(
    api_client: ApiClient, role_type: str
) -> ApiRoleConfigGroup:
    rcg_api = MgmtRoleConfigGroupsResourceApi(api_client)
    rcgs = [
        r
        for r in rcg_api.read_role_config_groups().items
        if r.role_type == role_type and r.base
    ]
    if len(rcgs) != 1:
        raise BaseRoleConfigGroupDiscoveryException(role_count=len(rcgs))
    else:
        return rcgs[0]


def get_role_config_group(
    api_client: ApiClient, cluster_name: str, service_name: str, name: str
) -> ApiRoleConfigGroup:
    rcg_api = RoleConfigGroupsResourceApi(api_client)

    rcg = rcg_api.read_role_config_group(cluster_name, name, service_name)

    if rcg is None:
        raise RoleConfigGroupDiscoveryException(name)
    else:
        return rcg


def reconcile_role_config_group(
    api_client: ApiClient, existing: ApiRoleConfigGroup, updates: dict
):
    pass
