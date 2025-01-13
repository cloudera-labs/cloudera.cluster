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
    ApiRoleState,
    HostsResourceApi,
    MgmtRolesResourceApi,
)

from ansible_collections.cloudera.cluster.plugins.modules import cm_service_role
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def test_missing_required(conn, module_args):
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="type"):
        cm_service_role.main()


def test_mutually_exclusive(conn, module_args):
    module_args({**conn, "cluster_hostname": "hostname", "cluster_host_id": "host_id"})

    with pytest.raises(
        AnsibleFailJson,
        match="parameters are mutually exclusive: cluster_hostname|cluster_host_id",
    ):
        cm_service_role.main()


def test_existing_relocate(conn, module_args, cm_api_client, host_monitor, request):
    host_api = HostsResourceApi(cm_api_client)
    host = next(
        (
            h
            for h in host_api.read_hosts().items
            if not h.cluster_ref and h.host_id != host_monitor.host_ref.host_id
        ),
        None,
    )
    if host is None:
        raise Exception("No available hosts to relocate Cloudera Manager Service role")

    module_args(
        {
            **conn,
            "type": host_monitor.type,
            "cluster_host_id": host.host_id,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert e.value.role["host_id"] == host.host_id

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert e.value.role["host_id"] == host.host_id


def test_new(conn, module_args, cm_api_client, cms, request):
    host_api = HostsResourceApi(cm_api_client)
    host = next((h for h in host_api.read_hosts().items if not h.cluster_ref), None)

    if host is None:
        raise Exception("No available hosts to assign Cloudera Manager Service role")

    module_args(
        {
            **conn,
            "type": "HOSTMONITOR",
            "cluster_host_id": host.host_id,
            "config": dict(mgmt_num_descriptor_fetch_tries=55),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    expected = dict(mgmt_num_descriptor_fetch_tries="55")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role["config"].items()


def test_new_maintenance_mode_enabled(conn, module_args, cm_api_client, cms, request):
    host_api = HostsResourceApi(cm_api_client)
    host = next((h for h in host_api.read_hosts().items if not h.cluster_ref), None)

    if host is None:
        raise Exception("No available hosts to assign Cloudera Manager Service role")

    module_args(
        {
            **conn,
            "type": "HOSTMONITOR",
            "cluster_host_id": host.host_id,
            "maintenance": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert e.value.role["maintenance_mode"] == True

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert e.value.role["maintenance_mode"] == True


@pytest.mark.role_config(
    dict(mgmt_num_descriptor_fetch_tries=11, process_start_secs=21)
)
def test_existing_set(conn, module_args, host_monitor_config, request):
    module_args(
        {
            **conn,
            "type": host_monitor_config.type,
            "config": dict(mgmt_num_descriptor_fetch_tries=55),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    expected = dict(mgmt_num_descriptor_fetch_tries="55", process_start_secs="21")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role["config"].items()


@pytest.mark.role_config(
    dict(mgmt_num_descriptor_fetch_tries=12, process_start_secs=22)
)
def test_existing_unset(conn, module_args, host_monitor_config, request):
    module_args(
        {
            **conn,
            "type": host_monitor_config.type,
            "config": dict(mgmt_num_descriptor_fetch_tries=None),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        }
    )

    expected = dict(process_start_secs="22")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role["config"].items()


@pytest.mark.role_config(
    dict(mgmt_num_descriptor_fetch_tries=13, process_start_secs=23)
)
def test_existing_purge(conn, module_args, host_monitor_config, request):
    module_args(
        {
            **conn,
            "type": host_monitor_config.type,
            "config": dict(mgmt_num_descriptor_fetch_tries=33),
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    expected = dict(mgmt_num_descriptor_fetch_tries="33")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role["config"].items()


@pytest.mark.role_config(
    dict(mgmt_num_descriptor_fetch_tries=14, process_start_secs=24)
)
def test_existing_purge_all(conn, module_args, host_monitor_config, request):
    module_args(
        {
            **conn,
            "type": host_monitor_config.type,
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert len(e.value.role["config"]) == 0

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert len(e.value.role["config"]) == 0


def test_existing_maintenance_mode_enabled(
    conn, module_args, cm_api_client, host_monitor, request
):
    module_args(
        {
            **conn,
            "type": host_monitor.type,
            "maintenance": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    role_api = MgmtRolesResourceApi(cm_api_client)
    role_api.exit_maintenance_mode(host_monitor.name)

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert e.value.role["maintenance_mode"] == True

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert e.value.role["maintenance_mode"] == True


def test_existing_maintenance_mode_disabled(
    conn, module_args, cm_api_client, host_monitor, request
):
    module_args(
        {
            **conn,
            "type": host_monitor.type,
            "maintenance": False,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    # TODO Turn this into a fixture - host_monitor_maintenance
    role_api = MgmtRolesResourceApi(cm_api_client)
    role_api.enter_maintenance_mode(host_monitor.name)

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert e.value.role["maintenance_mode"] == False

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert e.value.role["maintenance_mode"] == False


def test_existing_state_present(conn, module_args, host_monitor, request):
    module_args(
        {
            **conn,
            "type": host_monitor.type,
            "state": "present",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert e.value.role

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert e.value.role


@pytest.mark.role_state(ApiRoleState.STOPPED)
def test_existing_state_started(
    conn, module_args, cms_auto, host_monitor_state, request
):
    module_args(
        {
            **conn,
            "type": host_monitor_state.type,
            "state": "started",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert e.value.role["role_state"] == ApiRoleState.STARTED

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert e.value.role["role_state"] == ApiRoleState.STARTED


@pytest.mark.role_state(ApiRoleState.STARTED)
def test_existing_state_stopped(
    conn, module_args, cms_auto, host_monitor_state, request
):
    module_args(
        {
            **conn,
            "type": host_monitor_state.type,
            "state": "stopped",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert e.value.role["role_state"] == ApiRoleState.STOPPED

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert e.value.role["role_state"] == ApiRoleState.STOPPED


@pytest.mark.role_state(ApiRoleState.STARTED)
def test_existing_state_restarted(
    conn, module_args, cms_auto, host_monitor_state, request
):
    module_args(
        {
            **conn,
            "type": host_monitor_state.type,
            "state": "restarted",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert e.value.role["role_state"] == ApiRoleState.STARTED

    # Idempotency (restart always forces a changed state)
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert e.value.role["role_state"] == ApiRoleState.STARTED


def test_existing_state_absent(conn, module_args, cms_auto, host_monitor, request):
    module_args(
        {
            **conn,
            "type": host_monitor.type,
            "state": "absent",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert not e.value.role

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert not e.value.role
