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
import pytest

from ansible_collections.cloudera.cluster.plugins.modules import cm_service
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def test_minimal(conn, module_args, cms):
    module_args(conn)

    with pytest.raises(AnsibleExitJson):
        cm_service.main()


@pytest.mark.service_config(dict(log_event_retry_frequency=10))
def test_set_parameters(conn, module_args, cms_service_config):
    module_args(
        {
            **conn,
            "parameters": dict(mgmt_emit_sensitive_data_in_stderr=True),
            "message": "test_cm_service::test_set_parameters",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    expected = dict(
        mgmt_emit_sensitive_data_in_stderr="True", log_event_retry_frequency="10"
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert (
        expected.items()
        <= {c["name"]: c["value"] for c in e.value.service["config"]}.items()
    )

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert (
        expected.items()
        <= {c["name"]: c["value"] for c in e.value.service["config"]}.items()
    )


@pytest.mark.service_config(
    dict(mgmt_emit_sensitive_data_in_stderr=True, log_event_retry_frequency=10)
)
def test_unset_parameters(conn, module_args, cms_service_config):
    module_args(
        {
            **conn,
            "parameters": dict(mgmt_emit_sensitive_data_in_stderr=None),
            "message": "test_cm_service::test_unset_parameters",
        }
    )

    expected = dict(log_event_retry_frequency="10")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert (
        expected.items()
        <= {c["name"]: c["value"] for c in e.value.service["config"]}.items()
    )

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert (
        expected.items()
        <= {c["name"]: c["value"] for c in e.value.service["config"]}.items()
    )


@pytest.mark.service_config(
    dict(mgmt_emit_sensitive_data_in_stderr=True, log_event_retry_frequency=10)
)
def test_set_parameters_with_purge(conn, module_args, cms_service_config):
    module_args(
        {
            **conn,
            "parameters": dict(mgmt_emit_sensitive_data_in_stderr=True),
            "purge": True,
            "message": "test_cm_service::test_set_parameters_with_purge",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    expected = dict(mgmt_emit_sensitive_data_in_stderr="True")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert (
        expected.items()
        <= {c["name"]: c["value"] for c in e.value.service["config"]}.items()
    )

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert (
        expected.items()
        <= {c["name"]: c["value"] for c in e.value.service["config"]}.items()
    )


@pytest.mark.service_config(
    dict(mgmt_emit_sensitive_data_in_stderr=True, log_event_retry_frequency=10)
)
def test_purge_all_parameters(conn, module_args, cms_service_config):
    module_args(
        {
            **conn,
            "parameters": dict(),
            "purge": True,
            "message": "test_cm_service::test_purge_all_parameters",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert len(e.value.service["config"]) == 0

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert len(e.value.service["config"]) == 0
