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

from cm_client import ApiRoleConfigGroup


ROLE_CONFIG_GROUP = [
    "name",
    "role_type",
    "base",
    "display_name",
    # "service_ref",
]


def parse_role_config_group_result(role_config_group: ApiRoleConfigGroup) -> dict:
    # Retrieve only the service identifier
    output = dict(service_name=role_config_group.service_ref.service_name)
    output.update(normalize_output(role_config_group.to_dict(), ROLE_CONFIG_GROUP))
    return output
