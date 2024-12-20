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

from collections.abc import Generator
from pathlib import Path

from cm_client import (
    ApiConfig,
    ApiConfigList,
    ApiRole,
    ClustersResourceApi,
    MgmtRolesResourceApi,
)

from ansible_collections.cloudera.cluster.plugins.modules import cm_service_role
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
    provision_cm_role,
    cm_role_config,
)

LOG = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def host_monitor(cm_api_client, cms, request) -> Generator[ApiRole]:
    api = MgmtRolesResourceApi(cm_api_client)

    hm = next(
        iter([r for r in api.read_roles().items if r.type == "HOSTMONITOR"]), None
    )

    if hm is not None:
        yield hm
    else:
        cluster_api = ClustersResourceApi(cm_api_client)

        # Get first host of the cluster
        hosts = cluster_api.list_hosts(cluster_name=cms.cluster_ref.cluster_name)

        if not hosts.items:
            raise Exception(
                "No available hosts to assign the Cloudera Manager Service role."
            )
        else:
            name = Path(request.fixturename).stem
            yield from provision_cm_role(
                cm_api_client, name, "HOSTMONITOR", hosts.items[0].hostId
            )


@pytest.fixture(scope="function")
def host_monitor_config(cm_api_client, host_monitor, request) -> Generator[ApiRole]:
    marker = request.node.get_closest_marker("role_config")

    if marker is None:
        raise Exception("No role_config marker found.")

    yield from cm_role_config(
        api_client=cm_api_client,
        role=host_monitor,
        params=marker.args[0],
        message=f"{Path(request.node.parent.name).stem}::{request.node.name}",
    )


def test_missing_required(conn, module_args):
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="parameters"):
        cm_service_role.main()


def test_missing_required_if(conn, module_args):
    module_args(
        {
            **conn,
            "parameters": dict(),
        }
    )

    with pytest.raises(AnsibleFailJson, match="name, type"):
        cm_service_role.main()


def test_present_invalid_parameter(conn, module_args, host_monitor):
    module_args(
        {
            **conn,
            "role": host_monitor.name,
            "parameters": dict(example="Example"),
        }
    )

    with pytest.raises(
        AnsibleFailJson, match="Unknown configuration attribute 'example'"
    ):
        cm_service_role.main()


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
def test_set_parameters(conn, module_args, host_monitor_state, request):
    module_args(
        {
            **conn,
            "type": host_monitor_state.type,
            "config": dict(mgmt_num_descriptor_fetch_tries=32),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    expected = dict(mgmt_num_descriptor_fetch_tries="32", process_start_secs="21")

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
    dict(mgmt_num_descriptor_fetch_tries=11, process_start_secs=21)
)
def test_set_parameters_role_type(conn, module_args, host_monitor_config, request):
    module_args(
        {
            **conn,
            "role_type": host_monitor_config.type,
            "parameters": dict(mgmt_num_descriptor_fetch_tries=32),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    expected = dict(mgmt_num_descriptor_fetch_tries="32", process_start_secs="21")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config.main()

    assert e.value.changed == True
    assert expected.items() <= {c["name"]: c["value"] for c in e.value.config}.items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config.main()

    assert e.value.changed == False
    assert expected.items() <= {c["name"]: c["value"] for c in e.value.config}.items()


@pytest.mark.role_config(
    dict(mgmt_num_descriptor_fetch_tries=11, process_start_secs=21)
)
def test_unset_parameters(conn, module_args, host_monitor_config, request):
    module_args(
        {
            **conn,
            "role": host_monitor_config.name,
            "parameters": dict(mgmt_num_descriptor_fetch_tries=None),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        }
    )

    expected = dict(process_start_secs="21")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config.main()

    assert e.value.changed == True
    assert expected.items() <= {c["name"]: c["value"] for c in e.value.config}.items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config.main()

    assert e.value.changed == False
    assert expected.items() <= {c["name"]: c["value"] for c in e.value.config}.items()


@pytest.mark.role_config(
    dict(mgmt_num_descriptor_fetch_tries=11, process_start_secs=21)
)
def test_unset_parameters_role_type(conn, module_args, host_monitor_config, request):
    module_args(
        {
            **conn,
            "type": host_monitor_config.type,
            "parameters": dict(mgmt_num_descriptor_fetch_tries=None),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        }
    )

    expected = dict(process_start_secs="21")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config.main()

    assert e.value.changed == True
    assert expected.items() <= {c["name"]: c["value"] for c in e.value.config}.items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config.main()

    assert e.value.changed == False
    assert expected.items() <= {c["name"]: c["value"] for c in e.value.config}.items()


@pytest.mark.role_config(
    dict(mgmt_num_descriptor_fetch_tries=11, process_start_secs=21)
)
def test_set_parameters_with_purge(conn, module_args, host_monitor_config, request):
    module_args(
        {
            **conn,
            "role": host_monitor_config.name,
            "parameters": dict(mgmt_num_descriptor_fetch_tries=32),
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    expected = dict(mgmt_num_descriptor_fetch_tries="32")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config.main()

    assert e.value.changed == True
    assert expected.items() <= {c["name"]: c["value"] for c in e.value.config}.items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config.main()

    assert e.value.changed == False
    assert expected.items() <= {c["name"]: c["value"] for c in e.value.config}.items()


@pytest.mark.role_config(
    dict(mgmt_num_descriptor_fetch_tries=11, process_start_secs=21)
)
def test_set_parameters_with_purge_role_type(
    conn, module_args, host_monitor_config, request
):
    module_args(
        {
            **conn,
            "role_type": host_monitor_config.type,
            "parameters": dict(mgmt_num_descriptor_fetch_tries=32),
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    expected = dict(mgmt_num_descriptor_fetch_tries="32")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config.main()

    assert e.value.changed == True
    assert expected.items() <= {c["name"]: c["value"] for c in e.value.config}.items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config.main()

    assert e.value.changed == False
    assert expected.items() <= {c["name"]: c["value"] for c in e.value.config}.items()


@pytest.mark.role_config(
    dict(mgmt_num_descriptor_fetch_tries=11, process_start_secs=21)
)
def test_purge_all_parameters(conn, module_args, host_monitor_config, request):
    module_args(
        {
            **conn,
            "role": host_monitor_config.name,
            "parameters": dict(),
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config.main()

    assert e.value.changed == True
    assert len(e.value.config) == 0

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config.main()

    assert e.value.changed == False
    assert len(e.value.config) == 0


@pytest.mark.role_config(
    dict(mgmt_num_descriptor_fetch_tries=11, process_start_secs=21)
)
def test_purge_all_parameters_role_type(
    conn, module_args, host_monitor_config, request
):
    module_args(
        {
            **conn,
            "type": host_monitor_config.type,
            "parameters": dict(),
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config.main()

    assert e.value.changed == True
    assert len(e.value.config) == 0

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config.main()

    assert e.value.changed == False
    assert len(e.value.config) == 0
