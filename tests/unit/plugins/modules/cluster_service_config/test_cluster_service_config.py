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

from ansible_collections.cloudera.cluster.plugins.modules import cluster_service_config
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

    with pytest.raises(AnsibleFailJson, match="cluster, parameters, service"):
        cluster_service_config.main()


def test_missing_service(conn, module_args):
    conn.update(service="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster, parameters"):
        cluster_service_config.main()


def test_missing_cluster(conn, module_args):
    conn.update(cluster="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="parameters, service"):
        cluster_service_config.main()


def test_missing_parameters(conn, module_args):
    conn.update(parameters=dict(test="example"))
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster, service"):
        cluster_service_config.main()


def test_present_invalid_cluster(conn, module_args):
    conn.update(
        cluster="example",
        service="example",
        parameters=dict(example="Example"),
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="Cluster does not exist"):
        cluster_service_config.main()


def test_present_invalid_service(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service="example",
        parameters=dict(example="Example"),
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="Service 'example' not found"):
        cluster_service_config.main()


def test_present_invalid_parameter(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        parameters=dict(example="Example"),
    )
    module_args(conn)

    with pytest.raises(
        AnsibleFailJson, match="Unknown configuration attribute 'example'"
    ):
        cluster_service_config.main()


def test_set_parameters(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        parameters=dict(autopurgeSnapRetainCount=9),
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service_config.main()

    assert e.value.changed == True
    assert {c["name"]: c["value"] for c in e.value.config}[
        "autopurgeSnapRetainCount"
    ] == "9"

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service_config.main()

    assert e.value.changed == False
    assert {c["name"]: c["value"] for c in e.value.config}[
        "autopurgeSnapRetainCount"
    ] == "9"


def test_unset_parameters(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        parameters=dict(autopurgeSnapRetainCount=None),
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service_config.main()

    assert e.value.changed == True
    results = {c["name"]: c["value"] for c in e.value.config}
    assert "autopurgeSnapRetainCount" not in results

    with pytest.raises(AnsibleExitJson) as e:
        cluster_service_config.main()

    assert e.value.changed == False
    results = {c["name"]: c["value"] for c in e.value.config}
    assert "autopurgeSnapRetainCount" not in results
