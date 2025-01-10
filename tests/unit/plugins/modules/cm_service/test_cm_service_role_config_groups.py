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
)

from ansible_collections.cloudera.cluster.plugins.modules import cm_service
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def test_new_role_config_group(conn, module_args, cms_cleared, request):
    expected = dict(alert_mailserver_username="FooBar")

    module_args(
        {
            **conn,
            "role_config_groups": [
                {
                    "type": "ALERTPUBLISHER",
                    "config": expected,
                }
            ],
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert len(e.value.service["role_config_groups"]) == 1
    assert (
        expected.items() <= e.value.service["role_config_groups"][0]["config"].items()
    )

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert len(e.value.service["role_config_groups"]) == 1
    assert (
        expected.items() <= e.value.service["role_config_groups"][0]["config"].items()
    )


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        role_type="HOSTMONITOR",
        config=ApiConfigList(
            items=[
                ApiConfig(name="mgmt_num_descriptor_fetch_tries", value=16),
                ApiConfig(name="process_start_secs", value=36),
            ]
        ),
    )
)
def test_existing_role_config_group_set(
    conn, module_args, host_monitor_role_group_config, request
):
    expected = dict(mgmt_num_descriptor_fetch_tries="16", process_start_secs="96")

    module_args(
        {
            **conn,
            "role_config_groups": [
                {
                    "type": "HOSTMONITOR",
                    "config": dict(process_start_secs="96"),
                }
            ],
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert len(e.value.service["role_config_groups"]) == 1
    assert (
        expected.items() <= e.value.service["role_config_groups"][0]["config"].items()
    )

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert len(e.value.service["role_config_groups"]) == 1
    assert (
        expected.items() <= e.value.service["role_config_groups"][0]["config"].items()
    )


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        role_type="HOSTMONITOR",
        config=ApiConfigList(
            items=[
                ApiConfig(name="mgmt_num_descriptor_fetch_tries", value=17),
                ApiConfig(name="process_start_secs", value=37),
            ]
        ),
    )
)
def test_existing_role_config_group_unset(
    conn, module_args, host_monitor_role_group_config, request
):
    expected = dict(
        mgmt_num_descriptor_fetch_tries="17",
    )

    module_args(
        {
            **conn,
            "role_config_groups": [
                {
                    "type": "HOSTMONITOR",
                    "config": dict(process_start_secs=None),
                }
            ],
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert len(e.value.service["role_config_groups"]) == 1
    assert (
        expected.items() <= e.value.service["role_config_groups"][0]["config"].items()
    )

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert len(e.value.service["role_config_groups"]) == 1
    assert (
        expected.items() <= e.value.service["role_config_groups"][0]["config"].items()
    )


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        role_type="HOSTMONITOR",
        config=ApiConfigList(
            items=[
                ApiConfig(name="mgmt_num_descriptor_fetch_tries", value=18),
                ApiConfig(name="process_start_secs", value=38),
            ]
        ),
    )
)
def test_existing_role_config_group_purge(
    conn, module_args, host_monitor_role_group_config, request
):
    expected = dict(
        mgmt_num_descriptor_fetch_tries="28",
    )

    module_args(
        {
            **conn,
            "role_config_groups": [
                {
                    "type": "HOSTMONITOR",
                    "config": dict(mgmt_num_descriptor_fetch_tries=28),
                }
            ],
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert len(e.value.service["role_config_groups"]) == 1
    assert (
        expected.items() <= e.value.service["role_config_groups"][0]["config"].items()
    )

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert len(e.value.service["role_config_groups"]) == 1
    assert (
        expected.items() <= e.value.service["role_config_groups"][0]["config"].items()
    )


@pytest.mark.role_config_group(
    ApiRoleConfigGroup(
        role_type="HOSTMONITOR",
        config=ApiConfigList(
            items=[
                ApiConfig(name="mgmt_num_descriptor_fetch_tries", value=18),
                ApiConfig(name="process_start_secs", value=38),
            ]
        ),
    )
)
def test_existing_role_config_group_purge_all(
    conn, module_args, host_monitor_role_group_config, request
):
    module_args(
        {
            **conn,
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert len(e.value.service["role_config_groups"]) == 0

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert len(e.value.service["role_config_groups"]) == 0
