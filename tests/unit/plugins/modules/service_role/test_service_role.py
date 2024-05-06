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

from ansible.module_utils.common.dict_transformations import recursive_diff

from ansible_collections.cloudera.cluster.plugins.modules import service_role
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

    with pytest.raises(AnsibleFailJson, match="cluster, role, service"):
        service_role.main()


def test_missing_service(conn, module_args):
    conn.update(service="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster, role"):
        service_role.main()


def test_missing_cluster(conn, module_args):
    conn.update(cluster="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="role, service"):
        service_role.main()


def test_missing_role(conn, module_args):
    conn.update(role="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster, service"):
        service_role.main()


def test_present_invalid_cluster(conn, module_args):
    conn.update(cluster="example", service="example", role="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="Cluster does not exist"):
        service_role.main()


def test_present_invalid_service(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service="example",
        role="example",
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="Service does not exist"):
        service_role.main()


def test_present_create_missing_all_requirements(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
    )
    module_args(conn)

    with pytest.raises(
        AnsibleFailJson,
        match="missing required arguments: cluster_host_id, cluster_hostname, type",
    ):
        service_role.main()


def test_present_create_missing_host(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        cluster_hostname=os.getenv("CM_CLUSTER_HOSTNAME"),
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="missing required arguments: type"):
        service_role.main()


def test_present_create_missing_type(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        type=os.getenv("CM_ROLE_TYPE"),
    )
    module_args(conn)

    with pytest.raises(
        AnsibleFailJson,
        match="missing required arguments: cluster_host_id, cluster_hostname",
    ):
        service_role.main()


def test_role(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        type=os.getenv("CM_ROLE_TYPE"),
        cluster_hostname=os.getenv("CM_CLUSTER_HOSTNAME"),
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert e.value.changed == True

    # with pytest.raises(AnsibleExitJson) as e:
    #     cluster_service_role.main()

    # assert e.value.changed == False


def test_role_generated_name(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        type=os.getenv("CM_ROLE_TYPE"),
        cluster_hostname=os.getenv("CM_CLUSTER_HOSTNAME"),
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert e.value.changed == True


def test_role_with_tags(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        type=os.getenv("CM_ROLE_TYPE"),
        cluster_hostname=os.getenv("CM_CLUSTER_HOSTNAME"),
        tags=dict(foo="test"),
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert e.value.changed == True


def test_role_with_maintenance(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        type=os.getenv("CM_ROLE_TYPE"),
        cluster_hostname=os.getenv("CM_CLUSTER_HOSTNAME"),
        maintenance=True,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert e.value.changed == True


def test_role_started(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        type=os.getenv("CM_ROLE_TYPE"),
        cluster_hostname=os.getenv("CM_CLUSTER_HOSTNAME"),
        state="started",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert e.value.changed == True


def test_role_type_update(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        type="HTTPFS",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert e.value.changed == True

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert e.value.changed == False


def test_role_maintenance_mode(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        maintenance="yes",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert e.value.role["maintenance_mode"] == True

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert e.value.role["maintenance_mode"] == True
    assert e.value.changed == False

    conn.update(
        maintenance="no",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert e.value.role["maintenance_mode"] == False

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert e.value.role["maintenance_mode"] == False
    assert e.value.changed == False


def test_role_set_tags(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        tags=dict(
            test="Ansible", key="Value", empty_string="", blank_string="  ", none=None
        ),
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert (
        recursive_diff(e.value.role["tags"], dict(test="Ansible", key="Value")) is None
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert (
        recursive_diff(e.value.role["tags"], dict(test="Ansible", key="Value")) is None
    )
    assert e.value.changed == False


def test_role_append_tags(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        tags=dict(more="Tags", key="Value"),
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert (
        recursive_diff(
            e.value.role["tags"], dict(test="Ansible", key="Value", more="Tags")
        )
        is None
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert (
        recursive_diff(
            e.value.role["tags"], dict(test="Ansible", key="Value", more="Tags")
        )
        is None
    )
    assert e.value.changed == False


@pytest.mark.skip("Move to separate DIFF test suite.")
def test_update_tags_check_mode(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        type="ZOOKEEPER",
        tags=dict(
            test="Ansible",
            empty_string="",
            none=None,
            long_empty_string="   ",
        ),
        _ansible_check_mode=True,
        _ansible_diff=True,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert e.value.changed == True
    assert e.value.diff["before"]["tags"] == dict()
    assert e.value.diff["after"]["tags"] == dict(test="Ansible")


def test_role_purge_tags(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        tags=dict(purge="Ansible"),
        purge=True,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert recursive_diff(e.value.role["tags"], dict(purge="Ansible")) is None
    assert e.value.changed == True

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert recursive_diff(e.value.role["tags"], dict(purge="Ansible")) is None
    assert e.value.changed == False


def test_started(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        state="started",
        _ansible_verbosity=3,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson):
        service_role.main()

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert e.value.changed == False


def test_stopped(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        state="stopped",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson):
        service_role.main()

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert e.value.changed == False


def test_absent(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        state="absent",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson):
        service_role.main()

    with pytest.raises(AnsibleExitJson) as e:
        service_role.main()

    assert e.value.changed == False
