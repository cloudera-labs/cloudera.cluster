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

from pathlib import Path

from cm_client import (
    ApiService,
    ApiServiceState,
    MgmtServiceResourceApi,
)

from ansible_collections.cloudera.cluster.plugins.modules import cm_service
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def test_state_present(conn, module_args, cms_cleared, request):
    module_args(
        {
            **conn,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False


def test_state_absent(conn, module_args, cm_api_client, cms_cleared, request):
    module_args(
        {
            **conn,
            "state": "absent",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        },
    )

    service_api = MgmtServiceResourceApi(cm_api_client)
    service_api.setup_cms(body=ApiService(type="MGMT"))

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert not e.value.service

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert not e.value.service


def test_state_absent_running_roles(conn, module_args, cms_auto, request):
    module_args(
        {
            **conn,
            "state": "absent",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert not e.value.service

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert not e.value.service


def test_state_started(conn, module_args, cm_api_client, cms_auto_no_start, request):
    module_args(
        {
            **conn,
            "state": "started",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert e.value.service["service_state"] == ApiServiceState.STARTED

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert e.value.service["service_state"] == ApiServiceState.STARTED


def test_state_stopped(conn, module_args, cm_api_client, cms_auto, request):
    module_args(
        {
            **conn,
            "state": "stopped",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert e.value.service["service_state"] == ApiServiceState.STOPPED

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert e.value.service["service_state"] == ApiServiceState.STOPPED


def test_state_restarted(conn, module_args, cm_api_client, cms_auto, request):
    module_args(
        {
            **conn,
            "state": "restarted",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert e.value.service["service_state"] == ApiServiceState.STARTED

    # Idempotency (rather, demonstrate that restart always invokes a changed state)
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert e.value.service["service_state"] == ApiServiceState.STARTED


def test_new_maintenance_enabled(conn, module_args, cms_cleared, request):
    module_args(
        {
            **conn,
            "maintenance": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert e.value.service["maintenance_mode"] == True

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert e.value.service["maintenance_mode"] == True


def test_new_config(conn, module_args, cms_cleared, request):
    module_args(
        {
            **conn,
            "parameters": dict(mgmt_emit_sensitive_data_in_stderr=True),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    expected = dict(mgmt_emit_sensitive_data_in_stderr="True")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.service["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.service["config"].items()


def test_existing_maintenance_enabled(conn, module_args, cm_api_client, cms, request):
    module_args(
        {
            **conn,
            "maintenance": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        },
    )

    service_api = MgmtServiceResourceApi(cm_api_client)
    service_api.exit_maintenance_mode()

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert e.value.service["maintenance_mode"] == True

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert e.value.service["maintenance_mode"] == True


def test_existing_maintenance_disabled(conn, module_args, cm_api_client, cms, request):
    module_args(
        {
            **conn,
            "maintenance": False,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        },
    )

    service_api = MgmtServiceResourceApi(cm_api_client)
    service_api.enter_maintenance_mode()

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert e.value.service["maintenance_mode"] == False

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert e.value.service["maintenance_mode"] == False


@pytest.mark.service_config(dict(log_event_retry_frequency=10))
def test_existing_set_parameters(conn, module_args, cms_config, request):
    module_args(
        {
            **conn,
            "parameters": dict(mgmt_emit_sensitive_data_in_stderr=True),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    expected = dict(
        mgmt_emit_sensitive_data_in_stderr="True",
        log_event_retry_frequency="10",
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.service["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.service["config"].items()


@pytest.mark.service_config(
    dict(mgmt_emit_sensitive_data_in_stderr=True, log_event_retry_frequency=10),
)
def test_existing_unset_parameters(conn, module_args, cms_config, request):
    module_args(
        {
            **conn,
            "parameters": dict(mgmt_emit_sensitive_data_in_stderr=None),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        },
    )

    expected = dict(log_event_retry_frequency="10")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.service["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.service["config"].items()


@pytest.mark.service_config(
    dict(mgmt_emit_sensitive_data_in_stderr=True, log_event_retry_frequency=10),
)
def test_existing_set_parameters_with_purge(conn, module_args, cms_config, request):
    module_args(
        {
            **conn,
            "parameters": dict(mgmt_emit_sensitive_data_in_stderr=True),
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    expected = dict(mgmt_emit_sensitive_data_in_stderr="True")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.service["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.service["config"].items()


@pytest.mark.service_config(
    dict(mgmt_emit_sensitive_data_in_stderr=True, log_event_retry_frequency=10),
)
def test_existing_purge_all_parameters(conn, module_args, cms_config, request):
    module_args(
        {
            **conn,
            "parameters": dict(),
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
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
