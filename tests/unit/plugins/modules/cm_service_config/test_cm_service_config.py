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

from ansible_collections.cloudera.cluster.plugins.modules import cm_service_config
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

    with pytest.raises(AnsibleFailJson, match="parameters"):
        cm_service_config.main()


def test_present_invalid_parameter(conn, module_args):
    conn.update(
        parameters=dict(example="Example"),
    )
    module_args(conn)

    with pytest.raises(
        AnsibleFailJson, match="Unknown configuration attribute 'example'"
    ):
        cm_service_config.main()


def test_set_parameters(conn, module_args):
    conn.update(
        parameters=dict(mgmt_emit_sensitive_data_in_stderr=True),
        # _ansible_check_mode=True,
        # _ansible_diff=True,
        message="test_cm_service_config::test_set_parameters",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_config.main()

    assert e.value.changed == True
    assert {c["name"]: c["value"] for c in e.value.config}[
        "mgmt_emit_sensitive_data_in_stderr"
    ] == "true"

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_config.main()

    assert e.value.changed == False
    assert {c["name"]: c["value"] for c in e.value.config}[
        "mgmt_emit_sensitive_data_in_stderr"
    ] == "true"


def test_unset_parameters(conn, module_args):
    conn.update(
        parameters=dict(mgmt_emit_sensitive_data_in_stderr=None),
        message="test_cm_service_config::test_unset_parameters",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_config.main()

    assert e.value.changed == True
    results = {c["name"]: c["value"] for c in e.value.config}
    assert "mgmt_emit_sensitive_data_in_stderr" not in results

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_config.main()

    # Idempotency
    assert e.value.changed == False
    results = {c["name"]: c["value"] for c in e.value.config}
    assert "mgmt_emit_sensitive_data_in_stderr" not in results


def test_set_parameters_with_purge(conn, module_args):
    conn.update(
        parameters=dict(mgmt_emit_sensitive_data_in_stderr=True),
        purge=True,
        message="test_cm_service_config::test_set_parameters_with_purge",
        # _ansible_check_mode=True,
        # _ansible_diff=True,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_config.main()

    assert e.value.changed == True
    assert {c["name"]: c["value"] for c in e.value.config}[
        "mgmt_emit_sensitive_data_in_stderr"
    ] == "true"

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_config.main()

    # Idempotency
    assert e.value.changed == False
    assert {c["name"]: c["value"] for c in e.value.config}[
        "mgmt_emit_sensitive_data_in_stderr"
    ] == "true"


def test_purge_all_parameters(conn, module_args):
    conn.update(
        parameters=dict(),
        purge=True,
        message="test_cm_service_config::test_purge_all_parameters",
        # _ansible_check_mode=True,
        # _ansible_diff=True,
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_config.main()

    assert e.value.changed == True
    assert len(e.value.config) == 0

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_config.main()

    assert e.value.changed == False
    assert len(e.value.config) == 0
