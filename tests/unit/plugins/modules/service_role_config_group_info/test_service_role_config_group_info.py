# -*- coding: utf-8 -*-

# Copyright 2024 Cloudera, Inc. All Rights Reserved.
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
import os
import pytest

from ansible_collections.cloudera.cluster.plugins.modules import (
    service_role_config_group_info,
)
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


@pytest.fixture()
def conn():
    conn = dict(username=os.getenv("CM_USERNAME"), password=os.getenv("CM_PASSWORD"))

    if os.getenv("CM_HOST", None):
        conn.update(host=os.getenv("CM_HOST"))

    if os.getenv("CM_PORT", None):
        conn.update(port=os.getenv("CM_PORT"))

    if os.getenv("CM_ENDPOINT", None):
        conn.update(url=os.getenv("CM_ENDPOINT"))

    if os.getenv("CM_PROXY", None):
        conn.update(proxy=os.getenv("CM_PROXY"))

    return {
        **conn,
        "verify_tls": "no",
        "debug": "no",
    }


def test_missing_required(conn, module_args):
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster, service"):
        service_role_config_group_info.main()


def test_missing_cluster(conn, module_args):
    conn.update(service="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster"):
        service_role_config_group_info.main()


def test_invalid_service(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": os.getenv("CM_CLUSTER"),
            "service": "BOOM",
        }
    )

    with pytest.raises(AnsibleFailJson, match="Service does not exist: BOOM"):
        service_role_config_group_info.main()


def test_invalid_cluster(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": "BOOM",
            "service": os.getenv("CM_SERVICE"),
        }
    )

    with pytest.raises(AnsibleFailJson, match="Cluster does not exist: BOOM"):
        service_role_config_group_info.main()


def test_view_all_role_config_groups(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": os.getenv("CM_CLUSTER"),
            "service": os.getenv("CM_SERVICE"),
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_info.main()

    assert len(e.value.role_config_groups) > 0


def test_view_service_role(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": os.getenv("CM_CLUSTER"),
            "service": os.getenv("CM_SERVICE"),
            "name": "hdfs-GATEWAY-BASE",
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_info.main()

    assert len(e.value.role_config_groups) == 1


@pytest.mark.skip("Requires hostname")
def test_view_service_roles_by_hostname(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": os.getenv("CM_CLUSTER"),
            "service": os.getenv("CM_SERVICE"),
            "cluster_hostname": "test07-worker-01.cldr.internal",
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_info.main()

    assert len(e.value.roles) == 2


@pytest.mark.skip("Requires host ID")
def test_view_service_roles_by_host_id(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": os.getenv("CM_CLUSTER"),
            "service": os.getenv("CM_SERVICE"),
            "cluster_host_id": "0b5fa17e-e316-4c86-8812-3108eb55b83d",
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_info.main()

    assert len(e.value.roles) == 4
