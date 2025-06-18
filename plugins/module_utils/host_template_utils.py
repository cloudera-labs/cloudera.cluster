# -*- coding: utf-8 -*-

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

from cm_client import (
    ApiClusterRef,
    ApiHostTemplate,
    ApiRoleConfigGroup,
    ApiRoleConfigGroupRef,
)


class HostTemplateException(Exception):
    pass


def parse_host_template(host_template: ApiHostTemplate) -> dict:
    return dict(
        name=host_template.name,
        cluster_name=host_template.cluster_ref.cluster_name,
        role_config_groups=[
            rcg_ref.role_config_group_name
            for rcg_ref in host_template.role_config_group_refs
        ],
    )


def create_host_template_model(
    cluster_name: str,
    name: str,
    role_config_groups: list[ApiRoleConfigGroup],
) -> ApiHostTemplate:

    rcg_refs = [
        ApiRoleConfigGroupRef(role_config_group_name=r.name) for r in role_config_groups
    ]

    return ApiHostTemplate(
        name=name,
        cluster_ref=ApiClusterRef(cluster_name=cluster_name),
        role_config_group_refs=rcg_refs,
    )
