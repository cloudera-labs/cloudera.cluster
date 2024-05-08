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
    service_role_config_group_config,
)
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


@pytest.fixture
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

    with pytest.raises(AnsibleFailJson, match="cluster, parameters, role_config_group, service"):
        service_role_config_group_config.main()


def test_missing_service(conn, module_args):
    conn.update(service="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster, parameters, role_config_group"):
        service_role_config_group_config.main()


def test_missing_cluster(conn, module_args):
    conn.update(cluster="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="parameters, role_config_group, service"):
        service_role_config_group_config.main()


def test_missing_role_config_group(conn, module_args):
    conn.update(role_config_group="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster, parameters, service"):
        service_role_config_group_config.main()

def test_missing_parameters(conn, module_args):
    conn.update(parameters={})
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster, role_config_group, service"):
        service_role_config_group_config.main()


def test_present_invalid_cluster(conn, module_args):
    conn.update(
        cluster="example",
        service="example",
        role_config_group="example",
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="Cluster does not exist: example"):
        service_role_config_group_config.main()


def test_present_invalid_service(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service="example",
        role_config_group="example",
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="Service does not exist: example"):
        service_role_config_group_config.main()


def test_present_missing_role_type(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role_config_group="hdfs_example",  # os.getenv("CM_ROLE_CONFIG_GROUP"),
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="missing required arguments: role_type"):
        service_role_config_group_config.main()


def test_create_role_config_group(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role_config_group="hdfs-example",  # os.getenv("CM_ROLE_CONFIG_GROUP"),
        role_type="DATANODE",
        # _ansible_check_mode=True,
        # _ansible_diff=True,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_config.main()

    assert e.value.changed == True
    assert e.value.role_config_group["name"] == "hdfs-example"
    assert e.value.role_config_group["roles"] == []

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_config.main()

    assert e.value.changed == False
    assert e.value.role_config_group["name"] == "hdfs-example"
    assert e.value.role_config_group["roles"] == []


def test_create_role_config_group_with_roles(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role_config_group="hdfs-example2",  # os.getenv("CM_ROLE_CONFIG_GROUP"),
        role_type="DATANODE",
        roles=["hdfs-DATANODE-a9a5b7d344404d8a304ff4b3779679a1"],
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_config.main()

    assert e.value.changed == True
    assert e.value.role_config_group["name"] == "hdfs-example2"
    assert e.value.role_config_group["roles"] == [
        "hdfs-DATANODE-a9a5b7d344404d8a304ff4b3779679a1"
    ]

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_config.main()

    assert e.value.changed == False
    assert e.value.role_config_group["name"] == "hdfs-example2"
    assert e.value.role_config_group["roles"] == [
        "hdfs-DATANODE-a9a5b7d344404d8a304ff4b3779679a1"
    ]


def test_update_role_membership(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role_config_group="hdfs-example2",  # os.getenv("CM_ROLE_CONFIG_GROUP"),
        role_type="DATANODE",
        roles=["hdfs-DATANODE-7f3a9da5805a46e3100bae67424355ac"],
        # _ansible_check_mode=True,
        # _ansible_diff=True,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_config.main()

    assert e.value.changed == True
    assert e.value.role_config_group["name"] == "hdfs-example2"
    assert e.value.role_config_group["roles"] == sorted(
        [
            "hdfs-DATANODE-a9a5b7d344404d8a304ff4b3779679a1",
            "hdfs-DATANODE-7f3a9da5805a46e3100bae67424355ac",
        ]
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_config.main()

    assert e.value.changed == False
    assert e.value.role_config_group["name"] == "hdfs-example2"
    assert e.value.role_config_group["roles"] == sorted(
        [
            "hdfs-DATANODE-a9a5b7d344404d8a304ff4b3779679a1",
            "hdfs-DATANODE-7f3a9da5805a46e3100bae67424355ac",
        ]
    )


def test_set_role_membership(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role_config_group="hdfs-example2",  # os.getenv("CM_ROLE_CONFIG_GROUP"),
        role_type="DATANODE",
        roles=["hdfs-DATANODE-7f3a9da5805a46e3100bae67424355ac"],
        purge=True,
        # _ansible_check_mode=True,
        # _ansible_diff=True,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_config.main()

    assert e.value.changed == True
    assert e.value.role_config_group["name"] == "hdfs-example2"
    assert e.value.role_config_group["roles"] == [
        "hdfs-DATANODE-7f3a9da5805a46e3100bae67424355ac"
    ]

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_config.main()

    assert e.value.changed == False
    assert e.value.role_config_group["name"] == "hdfs-example2"
    assert e.value.role_config_group["roles"] == [
        "hdfs-DATANODE-7f3a9da5805a46e3100bae67424355ac"
    ]


def test_purge_role_membership(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role_config_group="hdfs-example2",  # os.getenv("CM_ROLE_CONFIG_GROUP"),
        role_type="DATANODE",
        roles=[],
        purge=True,
        # _ansible_check_mode=True,
        # _ansible_diff=True,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_config.main()

    assert e.value.changed == True
    assert e.value.role_config_group["name"] == "hdfs-example2"
    assert not e.value.role_config_group["roles"]

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_config.main()

    assert e.value.changed == False
    assert e.value.role_config_group["name"] == "hdfs-example2"
    assert not e.value.role_config_group["roles"]
    

def test_remove_role_config_group(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role_config_group="hdfs-example",  # os.getenv("CM_ROLE_CONFIG_GROUP"),
        state="absent",
        # _ansible_check_mode=True,
        # _ansible_diff=True,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_config.main()

    assert e.value.changed == True
    assert not e.value.role_config_group

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_config.main()

    assert e.value.changed == False
    assert not e.value.role_config_group


def test_remove_role_config_group_with_roles(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role_config_group="hdfs-example2",  # os.getenv("CM_ROLE_CONFIG_GROUP"),
        state="absent",
        # _ansible_check_mode=True,
        # _ansible_diff=True,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_config.main()

    assert e.value.changed == True
    assert not e.value.role_config_group

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_group_config.main()

    assert e.value.changed == False
    assert not e.value.role_config_group


def test_remove_role_config_group_invalid_base(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role_config_group="hdfs-DATANODE-BASE",  # os.getenv("CM_ROLE_CONFIG_GROUP"),
        state="absent",
        # _ansible_check_mode=True,
        # _ansible_diff=True,
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="Group 'hdfs-DATANODE-BASE' is a base group"):
        service_role_config_group_config.main()
