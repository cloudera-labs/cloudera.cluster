# -*- coding: utf-8 -*-

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

"""
A common functions for Cloudera Manager cluster management
"""

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    normalize_output,
)

from cm_client import (
    ApiClient,
    ApiCluster,
    ApiHost,
    ClustersResourceApi,
    HostsResourceApi,
)


CLUSTER_OUTPUT = [
    "name",
    "display_name",
    # "full_version",
    "maintenance_mode",
    "maintenance_owners",
    # "services",
    # "parcels",
    "entity_status",
    "uuid",
    # "data_context_refs",
    "cluster_type",
    "tags",
]


def parse_cluster_result(cluster: ApiCluster) -> dict:
    # Retrieve full_version as version
    output = dict(version=cluster.full_version)
    output.update(normalize_output(cluster.to_dict(), CLUSTER_OUTPUT))
    return output


# TODO Convert to use cluster_name vs the ApiCluster object for broader usage in pytest fixtures
def get_cluster_hosts(api_client: ApiClient, cluster: ApiCluster) -> list[ApiHost]:
    hosts = (
        ClustersResourceApi(api_client)
        .list_hosts(
            cluster_name=cluster.name,
        )
        .items
    )

    host_api = HostsResourceApi(api_client)

    for h in hosts:
        h.config = host_api.read_host_config(
            host_id=h.host_id,
        )

    return hosts


def parse_control_plane_result(control_plane):
    """Parse a control plane API result into a dictionary format."""
    result = control_plane.to_dict()

    # Convert tags list to a more readable format if present
    if result.get("tags"):
        result["tags"] = [
            {"name": tag.name, "value": tag.value} for tag in control_plane.tags
        ]

    return result
