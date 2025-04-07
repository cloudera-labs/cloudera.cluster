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
    ConfigListUpdates,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    InvalidRoleTypeException,
)

from cm_client import (
    ApiClient,
    ApiConfig,
    ApiConfigList,
    ApiRoleConfigGroup,
    ApiRoleConfigGroupList,
    RoleConfigGroupsResourceApi,
    ServicesResourceApi,
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


def create_role_config_group(
    api_client: ApiClient,
    cluster_name: str,
    service_name: str,
    name: str,
    role_type: str,
    display_name: str = None,
    config: dict = None,
) -> ApiRoleConfigGroup:
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

    role_config_group = ApiRoleConfigGroup(
        name=name,
        role_type=role_type.upper(),
    )

    if display_name:
        role_config_group.display_name = display_name

    if config:
        role_config_group.config = ApiConfigList(
            items=[ApiConfig(name=k, value=v) for k, v in config.items()]
        )

    return role_config_group


def provision_role_config_groups(
    api_client: ApiClient,
    cluster_name: str,
    service_name: str,
    role_config_groups: list[ApiRoleConfigGroup],
) -> ApiRoleConfigGroup:
    return RoleConfigGroupsResourceApi(api_client).create_role_config_groups(
        cluster_name=cluster_name,
        service_name=service_name,
        body=ApiRoleConfigGroupList(items=role_config_groups),
    )


def update_role_config_group(
    role_config_group: ApiRoleConfigGroup,
    display_name: str = None,
    config: dict = None,
    purge: bool = False,
) -> tuple[ApiRoleConfigGroup, dict, dict]:
    before, after = dict(), dict()

    # Check for display name changes
    if display_name is not None and display_name != role_config_group.display_name:
        before.update(display_name=role_config_group.display_name)
        after.update(display_name=display_name)
        role_config_group.display_name = display_name

    # Reconcile configurations
    if config or purge:
        if config is None:
            config = dict()

        updates = ConfigListUpdates(role_config_group.config, config, purge)

        if updates.changed:
            before.update(config=updates.diff["before"])
            after.update(config=updates.diff["after"])
            role_config_group.config = updates.config

    return (role_config_group, before, after)


# TODO Normalize the return value to be a list
def get_base_role_config_group(
    api_client: ApiClient, cluster_name: str, service_name: str, role_type: str = None
) -> ApiRoleConfigGroup:
    base_rcg_list = [
        r
        for r in RoleConfigGroupsResourceApi(api_client)
        .read_role_config_groups(
            cluster_name=cluster_name,
            service_name=service_name,
        )
        .items
        if (r.base and role_type is None) or (r.base and r.role_type == role_type)
    ]
    if role_type is not None:
        return next(iter(base_rcg_list), None)
    else:
        return base_rcg_list


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
