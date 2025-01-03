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

from collections.abc import Generator
from pathlib import Path

from cm_client import (
    ApiConfig,
    ApiConfigList,
    ApiRole,
    ApiRoleList,
    ApiRoleState,
    ClustersResourceApi,
    MgmtRolesResourceApi,
)

from ansible_collections.cloudera.cluster.plugins.modules import cm_service_role
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
    set_cm_role,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.host_utils import (
    get_host_ref,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    get_mgmt_roles,
)

LOG = logging.getLogger(__name__)


@pytest.fixture(scope="function")
def target_cm_role(cm_api_client, cms, base_cluster, request) -> Generator[ApiRole]:
    marker = request.node.get_closest_marker("role")

    if marker is None:
        role = ApiRole(
            type="HOSTMONITOR",
        )
    else:
        role = marker.args[0]
        role.type = "HOSTMONITOR"

    yield from set_cm_role(cm_api_client, base_cluster, role)


@pytest.fixture(scope="function")
def target_cm_role_cleared(
    cm_api_client, base_cluster, host_monitor_cleared, request
) -> Generator[ApiRole]:
    marker = request.node.get_closest_marker("role")

    if marker is None:
        role = ApiRole(
            type="HOSTMONITOR",
        )
    else:
        role = marker.args[0]
        role.type = "HOSTMONITOR"

    role_api = MgmtRolesResourceApi(cm_api_client)

    if not role.host_ref:
        cluster_api = ClustersResourceApi(cm_api_client)

        # Get first host of the cluster
        hosts = cluster_api.list_hosts(cluster_name=base_cluster.name)

        if not hosts.items:
            raise Exception(
                "No available hosts to assign the Cloudera Manager Service role."
            )

        role.host_ref = get_host_ref(cm_api_client, host_id=hosts.items[0].host_id)

    # Create and yield the role under test
    current_role = next(
        iter(role_api.create_roles(body=ApiRoleList(items=[role])).items), None
    )
    current_role.config = role_api.read_role_config(role_name=current_role.name)

    yield current_role

    # Clear out any remaining roles
    remaining_roles = get_mgmt_roles(cm_api_client, "HOSTMONITOR")

    for r in remaining_roles.items:
        role_api.delete_role(role_name=r.name)


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


@pytest.mark.role(ApiRole())
def test_relocate_host(
    conn, module_args, cm_api_client, base_cluster, target_cm_role_cleared, request
):
    cluster_api = ClustersResourceApi(cm_api_client)

    # Get second host of the cluster
    hosts = cluster_api.list_hosts(cluster_name=base_cluster.name)

    if not hosts.items:
        raise Exception(
            "No available hosts to assign the Cloudera Manager Service role."
        )
    filtered_hosts = [
        h for h in hosts.items if h.host_id != target_cm_role_cleared.host_ref.host_id
    ]

    if len(filtered_hosts) < 1:
        raise Exception(
            "Not enough hosts to reassign the Cloudera Manager Service role."
        )

    module_args(
        {
            **conn,
            "type": target_cm_role_cleared.type,
            "cluster_hostname": filtered_hosts[0].hostname,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    expected = filtered_hosts[0].host_id

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert expected == e.value.role["host_id"]

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert expected == e.value.role["host_id"]


@pytest.mark.role(
    ApiRole(
        config=ApiConfigList(
            items=[
                ApiConfig("mgmt_num_descriptor_fetch_tries", 11),
                ApiConfig("process_start_secs", 21),
            ]
        )
    )
)
def test_set_config(conn, module_args, target_cm_role, request):
    module_args(
        {
            **conn,
            "type": target_cm_role.type,
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


@pytest.mark.role(
    ApiRole(
        config=ApiConfigList(
            items=[
                ApiConfig("mgmt_num_descriptor_fetch_tries", 12),
                ApiConfig("process_start_secs", 22),
            ]
        )
    )
)
def test_unset_config(conn, module_args, target_cm_role, request):
    module_args(
        {
            **conn,
            "type": target_cm_role.type,
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


@pytest.mark.role(
    ApiRole(
        config=ApiConfigList(
            items=[
                ApiConfig("mgmt_num_descriptor_fetch_tries", 13),
                ApiConfig("process_start_secs", 23),
            ]
        )
    )
)
def test_set_config_purge(conn, module_args, target_cm_role, request):
    module_args(
        {
            **conn,
            "type": target_cm_role.type,
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


@pytest.mark.role(
    ApiRole(
        config=ApiConfigList(
            items=[
                ApiConfig("mgmt_num_descriptor_fetch_tries", 14),
                ApiConfig("process_start_secs", 24),
            ]
        )
    )
)
def test_set_config_purge_all(conn, module_args, target_cm_role, request):
    module_args(
        {
            **conn,
            "type": target_cm_role.type,
            "config": dict(),
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


@pytest.mark.role(ApiRole(maintenance_mode=False))
def test_maintenance_mode_enabled(conn, module_args, target_cm_role, request):
    module_args(
        {
            **conn,
            "type": target_cm_role.type,
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


@pytest.mark.role(ApiRole(maintenance_mode=True))
def test_maintenance_mode_disabled(conn, module_args, target_cm_role, request):
    module_args(
        {
            **conn,
            "type": target_cm_role.type,
            "maintenance": False,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert e.value.role["maintenance_mode"] == False

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert e.value.role["maintenance_mode"] == False


@pytest.mark.role(ApiRole(role_state=ApiRoleState.STOPPED))
def test_state_started(conn, module_args, target_cm_role, request):
    module_args(
        {
            **conn,
            "type": target_cm_role.type,
            "state": "started",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert e.value.role["role_state"] == "STARTED"

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert e.value.role["role_state"] == "STARTED"


@pytest.mark.role(ApiRole(role_state=ApiRoleState.STARTED))
def test_state_started(conn, module_args, target_cm_role, request):
    module_args(
        {
            **conn,
            "type": target_cm_role.type,
            "state": "stopped",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert e.value.role["role_state"] == "STOPPED"

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == False
    assert e.value.role["role_state"] == "STOPPED"


@pytest.mark.role(ApiRole(role_state=ApiRoleState.STOPPED))
def test_state_restarted(conn, module_args, target_cm_role, request):
    module_args(
        {
            **conn,
            "type": target_cm_role.type,
            "state": "restarted",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert e.value.role["role_state"] == "STARTED"

    # Idempotency is not possible due to this state
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role.main()

    assert e.value.changed == True
    assert e.value.role["role_state"] == "STARTED"


def test_state_absent(conn, module_args, target_cm_role_cleared, request):
    module_args(
        {
            **conn,
            "type": target_cm_role_cleared.type,
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
