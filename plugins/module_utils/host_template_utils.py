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
A common functions for Cloudera Manager host templates
"""

HOST_TEMPLATE_OUTPUT = ["name", "cluster_ref", "role_config_group_refs"]


def _parse_host_template_output(host_template: dict) -> dict:
    result = _parse_output(host_template, HOST_TEMPLATE_OUTPUT)
    result["cluster_name"] = result["cluster_ref"]["cluster_name"]
    result["role_groups"] = [
        role["role_config_group_name"] for role in result["role_config_group_refs"]
    ]
    del result["cluster_ref"]
    del result["role_config_group_refs"]
    return result


def _parse_host_templates_output(host_templates: list) -> list:
    parsed_templates = [template.to_dict() for template in host_templates]
    return [
        _parse_host_template_output(template_dict) for template_dict in parsed_templates
    ]


def _parse_output(host_template: dict, keys: list) -> dict:
    return {key: host_template[key] for key in keys if key in host_template}
