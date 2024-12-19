#!/usr/bin/python
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

from pathlib import Path

from cm_client import (
    ApiConfig,
    ApiConfigList,
    ApiRoleConfigGroup,
)

from ansible_collections.cloudera.cluster.plugins.modules import (
    cm_service_role_config_group,
)
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        config=ApiConfigList(
            items=[
                ApiConfig(k, v)
                for k, v in dict(
                    mgmt_num_descriptor_fetch_tries=11, process_start_secs=21
                ).items()
            ]
        )
    )
)
def test_cm_role_config_group_config_set(
    conn, module_args, host_monitor_config, request
):
    module_args(
        {
            **conn,
            "type": host_monitor_config.role_type,
            "parameters": dict(mgmt_num_descriptor_fetch_tries=32),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    expected = dict(mgmt_num_descriptor_fetch_tries="32", process_start_secs="21")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config_group.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role_config_group["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config_group.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role_config_group["config"].items()


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        config=ApiConfigList(
            items=[
                ApiConfig(k, v)
                for k, v in dict(
                    mgmt_num_descriptor_fetch_tries=11, process_start_secs=21
                ).items()
            ]
        )
    )
)
def test_cm_role_config_group_config_unset(
    conn, module_args, host_monitor_config, request
):
    module_args(
        {
            **conn,
            "type": host_monitor_config.role_type,
            "parameters": dict(mgmt_num_descriptor_fetch_tries=None),
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    expected = dict(process_start_secs="21")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config_group.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role_config_group["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config_group.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role_config_group["config"].items()


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        config=ApiConfigList(
            items=[
                ApiConfig(k, v)
                for k, v in dict(
                    mgmt_num_descriptor_fetch_tries=11, process_start_secs=21
                ).items()
            ]
        )
    )
)
def test_cm_role_config_group_config_set_purge(
    conn, module_args, host_monitor_config, request
):
    module_args(
        {
            **conn,
            "type": host_monitor_config.role_type,
            "parameters": dict(mgmt_num_descriptor_fetch_tries=32),
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    expected = dict(mgmt_num_descriptor_fetch_tries="32")

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config_group.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role_config_group["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config_group.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role_config_group["config"].items()


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        config=ApiConfigList(
            items=[
                ApiConfig(k, v)
                for k, v in dict(
                    mgmt_num_descriptor_fetch_tries=11, process_start_secs=21
                ).items()
            ]
        )
    )
)
def test_cm_role_config_group_config_purge_all(
    conn, module_args, host_monitor_config, request
):
    module_args(
        {
            **conn,
            "type": host_monitor_config.role_type,
            "parameters": dict(),
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    expected = dict()

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config_group.main()

    assert e.value.changed == True
    assert expected.items() <= e.value.role_config_group["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config_group.main()

    assert e.value.changed == False
    assert expected.items() <= e.value.role_config_group["config"].items()


@pytest.mark.role_config_group(ApiRoleConfigGroup(display_name="Test"))
def test_cm_role_config_group_display_name_set(
    conn, module_args, host_monitor_config, request
):
    expected = "Updated Test"

    module_args(
        {
            **conn,
            "type": host_monitor_config.role_type,
            "display_name": expected,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config_group.main()

    assert e.value.changed == True
    assert expected == e.value.role_config_group["display_name"]

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config_group.main()

    assert e.value.changed == False
    assert expected == e.value.role_config_group["display_name"]
