#!/usr/bin/python
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
    ApiConfig,
    ApiConfigList,
    ApiRoleConfigGroup,
    ApiRoleNameList,
    RoleConfigGroupsResourceApi,
)

from ansible_collections.cloudera.cluster.plugins.modules import (
    role_config_group,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    get_base_role_config_group,
)

from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def test_missing_required(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": "CLUSTER",
            "service": "SERVICE",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    with pytest.raises(AnsibleFailJson, match="name, role_type"):
        role_config_group.main()


def test_invalid_service(conn, module_args, base_cluster):
    module_args(
        {
            **conn,
            "cluster": base_cluster.name,
            "service": "BOOM",
            "type": "BOOM",
        },
    )

    with pytest.raises(AnsibleFailJson, match="Service does not exist: BOOM"):
        role_config_group.main()


def test_invalid_cluster(conn, module_args, cms_session):
    module_args(
        {
            **conn,
            "cluster": "BOOM",
            "service": "BOOM",
            "type": "BOOM",
        },
    )

    with pytest.raises(AnsibleFailJson, match="Cluster does not exist: BOOM"):
        role_config_group.main()


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        config=ApiConfigList(
            items=[
                ApiConfig(k, v)
                for k, v in dict(minSessionTimeout=2500, process_start_secs=25).items()
            ],
        ),
    ),
)
def test_base_role_config_group_set(conn, module_args, zk_role_config_group, request):
    module_args(
        {
            **conn,
            "cluster": zk_role_config_group.service_ref.cluster_name,
            "service": zk_role_config_group.service_ref.service_name,
            "type": zk_role_config_group.role_type,
            "parameters": dict(minSessionTimeout=3000),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    expected = dict(minSessionTimeout="3000", process_start_secs="25")

    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role_config_group["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role_config_group["config"].items()


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        config=ApiConfigList(
            items=[
                ApiConfig(k, v)
                for k, v in dict(minSessionTimeout=2600, process_start_secs=26).items()
            ],
        ),
    ),
)
def test_base_role_config_group_unset(conn, module_args, zk_role_config_group, request):
    module_args(
        {
            **conn,
            "cluster": zk_role_config_group.service_ref.cluster_name,
            "service": zk_role_config_group.service_ref.service_name,
            "type": zk_role_config_group.role_type,
            "parameters": dict(minSessionTimeout=None),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    expected = dict(process_start_secs="26")

    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role_config_group["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role_config_group["config"].items()


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        config=ApiConfigList(
            items=[
                ApiConfig(k, v)
                for k, v in dict(minSessionTimeout=2700, process_start_secs=27).items()
            ],
        ),
    ),
)
def test_base_role_config_group_purge(conn, module_args, zk_role_config_group, request):
    module_args(
        {
            **conn,
            "cluster": zk_role_config_group.service_ref.cluster_name,
            "service": zk_role_config_group.service_ref.service_name,
            "type": zk_role_config_group.role_type,
            "parameters": dict(minSessionTimeout=2701),
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    expected = dict(minSessionTimeout="2701")

    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role_config_group["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role_config_group["config"].items()


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        config=ApiConfigList(
            items=[
                ApiConfig(k, v)
                for k, v in dict(minSessionTimeout=2800, process_start_secs=28).items()
            ],
        ),
    ),
)
def test_base_role_config_group_purge_all(
    conn,
    module_args,
    zk_role_config_group,
    request,
):
    module_args(
        {
            **conn,
            "cluster": zk_role_config_group.service_ref.cluster_name,
            "service": zk_role_config_group.service_ref.service_name,
            "type": zk_role_config_group.role_type,
            "parameters": dict(),
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    expected = dict()

    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role_config_group["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role_config_group["config"].items()


def test_base_role_config_group_absent(
    conn,
    module_args,
    cm_api_client,
    zk_session,
    request,
):
    rcg = get_base_role_config_group(
        api_client=cm_api_client,
        cluster_name=zk_session.cluster_ref.cluster_name,
        service_name=zk_session.name,
        role_type="SERVER",
    )

    module_args(
        {
            **conn,
            "cluster": rcg.service_ref.cluster_name,
            "service": rcg.service_ref.service_name,
            "type": rcg.role_type,
            "state": "absent",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    with pytest.raises(
        AnsibleFailJson,
        match="Deletion failed\. Role config group is a base \(default\) group\.",
    ) as e:
        role_config_group.main()


def test_role_config_group_create(conn, module_args, zk_session, request):
    module_args(
        {
            **conn,
            "cluster": zk_session.cluster_ref.cluster_name,
            "service": zk_session.name,
            "type": "SERVER",
            "name": f"pyest-{zk_session.name}",
            "parameters": dict(minSessionTimeout=3000),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    expected = dict(minSessionTimeout="3000")

    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role_config_group["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role_config_group["config"].items()


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        name="Pytest Set",
        role_type="SERVER",
        config=ApiConfigList(
            items=[
                ApiConfig(k, v)
                for k, v in dict(minSessionTimeout=2800, process_start_secs=28).items()
            ],
        ),
    ),
)
def test_role_config_group_set(conn, module_args, zk_role_config_group, request):
    module_args(
        {
            **conn,
            "cluster": zk_role_config_group.service_ref.cluster_name,
            "service": zk_role_config_group.service_ref.service_name,
            "name": zk_role_config_group.name,
            "parameters": dict(minSessionTimeout=3000),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    expected = dict(minSessionTimeout="3000", process_start_secs="28")

    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role_config_group["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role_config_group["config"].items()


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        name="Pytest Set",
        role_type="SERVER",
        config=ApiConfigList(
            items=[
                ApiConfig(k, v)
                for k, v in dict(minSessionTimeout=2900, process_start_secs=29).items()
            ],
        ),
    ),
)
def test_role_config_group_unset(conn, module_args, zk_role_config_group, request):
    module_args(
        {
            **conn,
            "cluster": zk_role_config_group.service_ref.cluster_name,
            "service": zk_role_config_group.service_ref.service_name,
            "name": zk_role_config_group.name,
            "parameters": dict(minSessionTimeout=None),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    expected = dict(process_start_secs="29")

    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role_config_group["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role_config_group["config"].items()


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        name="Pytest Set",
        role_type="SERVER",
        config=ApiConfigList(
            items=[
                ApiConfig(k, v)
                for k, v in dict(minSessionTimeout=3100, process_start_secs=31).items()
            ],
        ),
    ),
)
def test_role_config_group_purge(conn, module_args, zk_role_config_group, request):
    module_args(
        {
            **conn,
            "cluster": zk_role_config_group.service_ref.cluster_name,
            "service": zk_role_config_group.service_ref.service_name,
            "name": zk_role_config_group.name,
            "parameters": dict(minSessionTimeout=3000),
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    expected = dict(minSessionTimeout="3000")

    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role_config_group["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role_config_group["config"].items()


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        name="Pytest Set",
        role_type="SERVER",
        config=ApiConfigList(
            items=[
                ApiConfig(k, v)
                for k, v in dict(minSessionTimeout=3200, process_start_secs=32).items()
            ],
        ),
    ),
)
def test_role_config_group_purge_all(conn, module_args, zk_role_config_group, request):
    module_args(
        {
            **conn,
            "cluster": zk_role_config_group.service_ref.cluster_name,
            "service": zk_role_config_group.service_ref.service_name,
            "name": zk_role_config_group.name,
            "parameters": dict(),
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    expected = dict()

    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role_config_group["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role_config_group["config"].items()


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        name="Pytest Set",
        role_type="SERVER",
        config=ApiConfigList(
            items=[
                ApiConfig(k, v)
                for k, v in dict(minSessionTimeout=3100, process_start_secs=31).items()
            ],
        ),
    ),
)
def test_role_config_group_absent(conn, module_args, zk_role_config_group, request):
    module_args(
        {
            **conn,
            "cluster": zk_role_config_group.service_ref.cluster_name,
            "service": zk_role_config_group.service_ref.service_name,
            "name": zk_role_config_group.name,
            "state": "absent",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == True
    assert not e.value.role_config_group

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        role_config_group.main()

    assert e.value.changed == False
    assert not e.value.role_config_group


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        name="Pytest Invalid Type",
        role_type="SERVER",
        config=ApiConfigList(items=[]),
    ),
)
def test_role_config_group_invalid_type(
    conn,
    module_args,
    zk_role_config_group,
    request,
):
    module_args(
        {
            **conn,
            "cluster": zk_role_config_group.service_ref.cluster_name,
            "service": zk_role_config_group.service_ref.service_name,
            "name": "Pytest Invalid Type",
            "type": "INVALID",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    with pytest.raises(AnsibleFailJson, match="Invalid role type") as e:
        role_config_group.main()


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        name="Pytest Invalid Configuration",
        role_type="SERVER",
        config=ApiConfigList(items=[]),
    ),
)
def test_role_config_group_invalid_config(
    conn,
    module_args,
    zk_role_config_group,
    request,
):
    module_args(
        {
            **conn,
            "cluster": zk_role_config_group.service_ref.cluster_name,
            "service": zk_role_config_group.service_ref.service_name,
            "name": "Pytest Invalid Configuration",
            "config": dict(invalid_configuration_parameter="BOOM"),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    with pytest.raises(AnsibleFailJson, match="Unknown configuration attribute") as e:
        role_config_group.main()


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        name="Pytest Absent",
        role_type="SERVER",
        config=ApiConfigList(items=[]),
    ),
)
def test_role_config_group_existing_roles(
    conn,
    module_args,
    cm_api_client,
    zk_role_config_group,
    request,
):
    base_rcg = get_base_role_config_group(
        api_client=cm_api_client,
        cluster_name=zk_role_config_group.service_ref.cluster_name,
        service_name=zk_role_config_group.service_ref.service_name,
        role_type="SERVER",
    )

    rcg_api = RoleConfigGroupsResourceApi(cm_api_client)
    role_list = rcg_api.read_roles(
        cluster_name=zk_role_config_group.service_ref.cluster_name,
        service_name=zk_role_config_group.service_ref.service_name,
        role_config_group_name=base_rcg.name,
    )

    rcg_api.move_roles(
        cluster_name=zk_role_config_group.service_ref.cluster_name,
        service_name=zk_role_config_group.service_ref.service_name,
        role_config_group_name="Pytest Absent",
        body=ApiRoleNameList(items=[role_list.items[0].name]),
    )

    module_args(
        {
            **conn,
            "cluster": zk_role_config_group.service_ref.cluster_name,
            "service": zk_role_config_group.service_ref.service_name,
            "name": "Pytest Absent",
            "state": "absent",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        },
    )

    with pytest.raises(AnsibleFailJson, match="existing role associations") as e:
        role_config_group.main()

    rcg_api.move_roles_to_base_group(
        cluster_name=zk_role_config_group.service_ref.cluster_name,
        service_name=zk_role_config_group.service_ref.service_name,
        body=ApiRoleNameList(items=[role_list.items[0].name]),
    )
