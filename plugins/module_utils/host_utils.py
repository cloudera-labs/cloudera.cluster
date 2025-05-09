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

from cm_client import (
    ApiClient,
    ApiConfig,
    ApiConfigList,
    ApiEntityTag,
    ApiHost,
    ApiHostRef,
    HostsResourceApi,
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    normalize_output,
)


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

    # Parse the role names (only the names)
    if host.role_refs is not None:
        output.update(
            roles=[r.role_name for r in host.role_refs],
        )

    return output


def get_host(
    api_client: ApiClient, hostname: str = None, host_id: str = None
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
    if hostname:
        return next(
            (
                h
                for h in HostsResourceApi(api_client).read_hosts().items
                if h.hostname == hostname
            ),
            None,
        )
    else:
        try:
            return HostsResourceApi(api_client).read_host(host_id)
        except ApiException as ex:
            if ex.status != 404:
                raise ex
            else:
                return None


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
