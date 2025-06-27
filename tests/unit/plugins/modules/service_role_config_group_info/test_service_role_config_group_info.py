# -*- coding: utf-8 -*-

# Copyright 2025 Cloudera, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
import pytest

from cm_client import (
    ApiConfigList,
    ApiRoleConfigGroup,
)

from ansible_collections.cloudera.cluster.plugins.modules import (
    service_role_config_group_info,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    get_base_role_config_group,
)
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def test_missing_required(conn, module_args):
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster, service"):
        service_role_config_group_info.main()


def test_missing_cluster(conn, module_args):
    module_args({**conn, "service": "example"})

    with pytest.raises(AnsibleFailJson, match="cluster"):
        service_role_config_group_info.main()


def test_missing_service(conn, module_args, base_cluster):
    module_args({**conn, "cluster": base_cluster.name})

    with pytest.raises(AnsibleFailJson, match="service"):
        service_role_config_group_info.main()


def test_invalid_service(conn, module_args, base_cluster):
    module_args(
        {
            **conn,
            "cluster": base_cluster.name,
            "service": "BOOM",
        },
    )

    with pytest.raises(AnsibleFailJson, match="Service does not exist: BOOM"):
        service_role_config_group_info.main()


def test_invalid_cluster(conn, module_args, cms_session):
    module_args(
        {
            **conn,
            "cluster": "BOOM",
            "service": "ShouldNotReach",
        },
    )

    with pytest.raises(AnsibleFailJson, match="Cluster does not exist: BOOM"):
        service_role_config_group_info.main()


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        name="Pytest All",
        role_type="SERVER",
        config=ApiConfigList(items=[]),
    ),
)
def test_all_role_config_groups(conn, module_args, base_cluster, zk_role_config_group):
    module_args(
        {
            **conn,
            "cluster": base_cluster.name,
            "service": zk_role_config_group.service_ref.service_name,
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_info.main()

    assert len(e.value.role_config_groups) == 2


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        name="Pytest Type",
        role_type="SERVER",
        config=ApiConfigList(items=[]),
    ),
)
def test_type_role_config_group(conn, module_args, base_cluster, zk_role_config_group):
    module_args(
        {
            **conn,
            "cluster": base_cluster.name,
            "service": zk_role_config_group.service_ref.service_name,
            "type": "SERVER",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_info.main()

    assert len(e.value.role_config_groups) == 2


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        name="Pytest Base",
        role_type="SERVER",
        config=ApiConfigList(items=[]),
    ),
)
def test_name_base_role_config_group(
    conn,
    module_args,
    cm_api_client,
    base_cluster,
    zk_role_config_group,
):
    base_rcg = get_base_role_config_group(
        api_client=cm_api_client,
        cluster_name=base_cluster.name,
        service_name=zk_role_config_group.service_ref.service_name,
        role_type="SERVER",
    )

    module_args(
        {
            **conn,
            "cluster": base_cluster.name,
            "service": zk_role_config_group.name,
            "name": base_rcg.name,
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_info.main()

    # Should be only one BASE for the SERVER
    assert len(e.value.role_config_groups) == 1
    assert e.value.role_config_groups[0]["base"] == True


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        name="Pytest Non-Base",
        role_type="SERVER",
        config=ApiConfigList(items=[]),
    ),
)
def test_name_base_role_config_group(
    conn,
    module_args,
    base_cluster,
    zk_role_config_group,
):
    module_args(
        {
            **conn,
            "cluster": base_cluster.name,
            "service": zk_role_config_group.service_ref.service_name,
            "name": "Pytest Non-Base",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_info.main()

    # Should be only one non-BASE for the SERVER
    assert len(e.value.role_config_groups) == 1
    assert e.value.role_config_groups[0]["base"] == False
