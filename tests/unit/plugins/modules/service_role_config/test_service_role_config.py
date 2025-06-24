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

from ansible_collections.cloudera.cluster.plugins.modules import service_role_config
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)

# Skip all tests due to pending removal of module from collection
pytestmark = pytest.mark.skip("Deprecated module")


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

    with pytest.raises(AnsibleFailJson, match="cluster, parameters, role, service"):
        service_role_config.main()


def test_missing_service(conn, module_args):
    conn.update(service="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster, parameters, role"):
        service_role_config.main()


def test_missing_cluster(conn, module_args):
    conn.update(cluster="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="parameters, role, service"):
        service_role_config.main()


def test_missing_parameters(conn, module_args):
    conn.update(parameters=dict(test="example"))
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster, role, service"):
        service_role_config.main()


def test_present_invalid_cluster(conn, module_args):
    conn.update(
        cluster="example",
        service="example",
        role="example",
        parameters=dict(example="Example"),
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="Cluster does not exist"):
        service_role_config.main()


def test_present_invalid_service(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service="example",
        role="example",
        parameters=dict(example="Example"),
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="Service does not exist"):
        service_role_config.main()


def test_present_invalid_role(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role="example",
        parameters=dict(example="Example"),
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="Role 'example' not found"):
        service_role_config.main()


def test_present_invalid_parameter(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        parameters=dict(example="Example"),
    )
    module_args(conn)

    with pytest.raises(
        AnsibleFailJson,
        match="Unknown configuration attribute 'example'",
    ):
        service_role_config.main()


def test_set_parameters(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        parameters={os.getenv("CM_ROLE_PARAM"): "DEBUG"},
        # _ansible_diff=True,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config.main()

    assert e.value.changed == True
    assert {c["name"]: c["value"] for c in e.value.config}[
        os.getenv("CM_ROLE_PARAM")
    ] == "DEBUG"

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config.main()

    assert e.value.changed == False
    assert {c["name"]: c["value"] for c in e.value.config}[
        os.getenv("CM_ROLE_PARAM")
    ] == "DEBUG"


def test_unset_parameters(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        parameters={os.getenv("CM_ROLE_PARAM"): None},
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config.main()

    assert e.value.changed == True
    assert not {c["name"]: c["value"] for c in e.value.config}.get(
        os.getenv("CM_ROLE_PARAM"),
        False,
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config.main()

    assert e.value.changed == False
    assert not {c["name"]: c["value"] for c in e.value.config}.get(
        os.getenv("CM_ROLE_PARAM"),
        False,
    )


def test_set_parameters_with_purge(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        parameters={os.getenv("CM_ROLE_PARAM2"): False},
        purge=True,
        # _ansible_diff=True,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config.main()

    assert e.value.changed == True
    assert {c["name"]: c["value"] for c in e.value.config}[
        os.getenv("CM_ROLE_PARAM2")
    ] == "false"
    assert not {c["name"]: c["value"] for c in e.value.config}.get(
        os.getenv("CM_ROLE_PARAM"),
        False,
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config.main()

    assert e.value.changed == False
    assert {c["name"]: c["value"] for c in e.value.config}[
        os.getenv("CM_ROLE_PARAM")
    ] == "DEBUG"


def test_purge_all_parameters(conn, module_args):
    conn.update(
        cluster=os.getenv("CM_CLUSTER"),
        service=os.getenv("CM_SERVICE"),
        role=os.getenv("CM_ROLE"),
        parameters=dict(),
        purge=True,
        # _ansible_check_mode=True,
        # _ansible_diff=True,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config.main()

    assert e.value.changed == True
    assert len(e.value.config) == 0

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config.main()

    assert e.value.changed == False
    assert len(e.value.config) == 0
