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

from ansible_collections.cloudera.cluster.plugins.modules import cluster_service
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


@pytest.fixture
def am_check_mode(am):
    am.check_mode = True
    yield am
    am.check_mode = False


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

    with pytest.raises(AnsibleFailJson, match="cluster, service"):
        cluster_service.main()


def test_missing_service(conn, module_args):
    conn.update(service="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster"):
        cluster_service.main()


def test_missing_cluster(conn, module_args):
    conn.update(cluster="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="service"):
        cluster_service.main()


def test_present_invalid_cluster(conn, module_args):
    conn.update(
        cluster="example",
        service="example",
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="Cluster does not exist"):
        cluster_service.main()


def test_present_missing_type(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="type"):
        cluster_service.main()


def test_present_create_service(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        display_name="Example Service",
        type="ZOOKEEPER",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert e.value.changed == True

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert e.value.changed == False


def test_present_update_service(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        display_name="Example Service by Ansible",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert e.value.changed == True

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert e.value.changed == False


def test_present_maintenance_mode(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        maintenance="yes",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert e.value.service["maintenance_mode"] == True

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert e.value.service["maintenance_mode"] == True
    assert e.value.changed == False

    conn.update(
        maintenance="no",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert e.value.service["maintenance_mode"] == False

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert e.value.service["maintenance_mode"] == False
    assert e.value.changed == False


def test_present_set_tags(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        tags=dict(
            test="Ansible", key="Value", empty_string="", blank_string="  ", none=None
        ),
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert (
        recursive_diff(e.value.service["tags"], dict(test="Ansible", key="Value"))
        is None
    )

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert (
        recursive_diff(e.value.service["tags"], dict(test="Ansible", key="Value"))
        is None
    )
    assert e.value.changed == False


def test_present_append_tags(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        tags=dict(more="Tags", key="Value"),
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert (
        recursive_diff(e.value.service["tags"], dict(test="Ansible", key="Value", more="Tags"))
        is None
    )

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert (
        recursive_diff(e.value.service["tags"], dict(test="Ansible", key="Value", more="Tags"))
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
        cluster_service.main()

    assert e.value.changed == True
    assert e.value.diff["before"]["tags"] == dict()
    assert e.value.diff["after"]["tags"] == dict(test="Ansible")


def test_present_purge_tags(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        tags=dict(purge="Ansible"),
        purge=True,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert (
        recursive_diff(e.value.service["tags"], dict(purge="Ansible"))
        is None
    )
    assert e.value.changed == True

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert (
        recursive_diff(e.value.service["tags"], dict(purge="Ansible"))
        is None
    )
    assert e.value.changed == False
    
def test_started(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        state="started",
        _ansible_verbosity=3,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson):
        cluster_service.main()

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert e.value.changed == False

def test_stopped(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        state="stopped",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson):
        cluster_service.main()

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert e.value.changed == False


def test_absent(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        state="absent",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson):
        cluster_service.main()

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service.main()

    assert e.value.changed == False
