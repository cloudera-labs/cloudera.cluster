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
A common functions for Cloudera Manager cluster management
"""

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    _parse_output,
)

from cm_client import ApiCluster


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
    output.update(_parse_output(cluster.to_dict(), CLUSTER_OUTPUT))
    return output
