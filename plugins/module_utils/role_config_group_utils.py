# Copyright 2025 Cloudera, Inc.
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
    return next(
        iter(
            [
                r
                for r in rcg_api.read_role_config_groups(
                    cluster_name, service_name
                ).items
                if r.role_type == role_type and r.base
            ]
        ),
        None,
    )


def get_mgmt_base_role_config_group(
    api_client: ApiClient, role_type: str
) -> ApiRoleConfigGroup:
    rcg_api = MgmtRoleConfigGroupsResourceApi(api_client)
    return next(
        iter(
            [
                r
                for r in rcg_api.read_role_config_groups().items
                if r.role_type == role_type and r.base
            ]
        ),
        None,
    )
