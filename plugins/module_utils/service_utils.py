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
A common functions for Cloudera Manager service management
"""

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    _parse_output,
)

from cm_client import ApiService

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
    # Retrieve only the cluster_name
    output = dict(cluster_name=service.cluster_ref.cluster_name)
    output.update(_parse_output(service.to_dict(), SERVICE_OUTPUT))
    return output
