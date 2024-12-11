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
    _parse_output,
    resolve_parameter_updates,
)

from cm_client import (
    ApiConfig,
    ApiService,
    ApiServiceConfig,
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
    # Retrieve only the cluster_name
    output = dict(cluster_name=service.cluster_ref.cluster_name)
    output.update(_parse_output(service.to_dict(), SERVICE_OUTPUT))
    return output


class ServiceConfigUpdates(object):
    def __init__(self, existing: ApiServiceConfig, updates: dict, purge: bool) -> None:
        current = {r.name: r.value for r in existing.items}
        changeset = resolve_parameter_updates(current, updates, purge)

        self.diff = dict(
            before={k: current[k] if k in current else None for k in changeset.keys()},
            after=changeset,
        )

        self.config = ApiServiceConfig(
            items=[ApiConfig(name=k, value=v) for k, v in changeset.items()]
        )

    @property
    def changed(self) -> bool:
        return bool(self.config.items)
