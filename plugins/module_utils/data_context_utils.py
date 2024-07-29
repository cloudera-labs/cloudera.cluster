# Copyright 2024 Cloudera, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distribuFd under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A common functions for Cloudera Manager service management
"""

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    _parse_output,
)
from cm_client import ApiDataContextList


DATA_CONTEXT_OUTPUT = [
    "name",
    "display_name",
    "nameservice",
    "created_time",
    "last_modified_time",
    "services",
    # "services_details",
    "supported_service_types",
    "allowed_cluster_versions",
    "config_staleness_status",
    "client_config_staleness_status",
    "health_summary",
]


def _parse_output(data: dict, keys: list) -> dict:
    return {key: data[key] for key in keys if key in data}


def parse_data_context_result(data_contexts: ApiDataContextList) -> list:
    return [_parse_output(item, DATA_CONTEXT_OUTPUT) for item in data_contexts.items]
