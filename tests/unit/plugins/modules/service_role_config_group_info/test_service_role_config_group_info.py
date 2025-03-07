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
    conn.update(service="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster"):
        service_role_config_group_info.main()


def test_invalid_service(conn, module_args, base_cluster):
    module_args(
        {
            **conn,
            "cluster": base_cluster.name,
            "service": "BOOM",
        }
    )

    with pytest.raises(AnsibleFailJson, match="Service does not exist: BOOM"):
        service_role_config_group_info.main()


def test_invalid_cluster(conn, module_args, base_cluster):
    module_args(
        {
            **conn,
            "cluster": "BOOM",
            "service": "ShouldNotReach",
        }
    )

    with pytest.raises(AnsibleFailJson, match="Cluster does not exist: BOOM"):
        service_role_config_group_info.main()


def test_all_role_config_groups(conn, module_args, base_cluster, zk_auto):
    module_args(
        {
            **conn,
            "cluster": base_cluster.name,
            "service": zk_auto.name,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_info.main()

    # Should be only one BASE for the SERVER
    assert len(e.value.role_config_groups) == 1
    assert e.value.role_config_groups[0]["base"] == True


def test_type_role_config_group(conn, module_args, base_cluster, zk_auto):
    module_args(
        {
            **conn,
            "cluster": base_cluster.name,
            "service": zk_auto.name,
            "type": "SERVER",
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_info.main()

    # Should be only one BASE for the SERVER
    assert len(e.value.role_config_groups) == 1
    assert e.value.role_config_groups[0]["base"] == True


def test_name_role_config_group(
    conn, module_args, cm_api_client, base_cluster, zk_auto
):
    base_rcg = get_base_role_config_group(
        api_client=cm_api_client,
        cluster_name=base_cluster.name,
        service_name=zk_auto.name,
        role_type="SERVER",
    )

    module_args(
        {
            **conn,
            "cluster": base_cluster.name,
            "service": zk_auto.name,
            "name": base_rcg.name,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_info.main()

    # Should be only one BASE for the SERVER
    assert len(e.value.role_config_groups) == 1
    assert e.value.role_config_groups[0]["base"] == True
