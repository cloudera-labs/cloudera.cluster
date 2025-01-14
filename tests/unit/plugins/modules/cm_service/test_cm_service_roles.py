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
    HostsResourceApi,
)

from ansible_collections.cloudera.cluster.plugins.modules import cm_service
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def test_new_role(conn, module_args, cm_api_client, cms_cleared, request):
    host_api = HostsResourceApi(cm_api_client)
    host = next((h for h in host_api.read_hosts().items if not h.cluster_ref), None)
    if host is None:
        raise Exception("No available hosts to assign Cloudera Manager Service role")

    module_args(
        {
            **conn,
            "roles": [
                {
                    "type": "HOSTMONITOR",
                    "cluster_host_id": host.host_id,
                }
            ],
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert len(e.value.service["roles"]) == 1
    assert not e.value.service["roles"][0]["config"]

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert len(e.value.service["roles"]) == 1
    assert not e.value.service["roles"][0]["config"]


def test_new_role_config(conn, module_args, cm_api_client, cms_cleared, request):
    host_api = HostsResourceApi(cm_api_client)
    host = next((h for h in host_api.read_hosts().items if not h.cluster_ref), None)
    if host is None:
        raise Exception("No available hosts to assign Cloudera Manager Service role")

    expected = dict(mgmt_num_descriptor_fetch_tries="15")

    module_args(
        {
            **conn,
            "roles": [
                {
                    "type": "HOSTMONITOR",
                    "cluster_host_id": host.host_id,
                    "config": expected,
                }
            ],
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert len(e.value.service["roles"]) == 1
    assert expected.items() <= e.value.service["roles"][0]["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert len(e.value.service["roles"]) == 1
    assert expected.items() <= e.value.service["roles"][0]["config"].items()


def test_existing_role_new(conn, module_args, cm_api_client, cms, request):
    host_api = HostsResourceApi(cm_api_client)
    host = next((h for h in host_api.read_hosts().items if not h.cluster_ref), None)
    if host is None:
        raise Exception("No available hosts to assign Cloudera Manager Service role")

    module_args(
        {
            **conn,
            "roles": [
                {
                    "type": "HOSTMONITOR",
                    "cluster_host_id": host.host_id,
                }
            ],
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert len(e.value.service["roles"]) == 1
    assert not e.value.service["roles"][0]["config"]

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert len(e.value.service["roles"]) == 1
    assert not e.value.service["roles"][0]["config"]


def test_existing_role_new_config_set(conn, module_args, cm_api_client, cms, request):
    host_api = HostsResourceApi(cm_api_client)
    host = next((h for h in host_api.read_hosts().items if not h.cluster_ref), None)
    if host is None:
        raise Exception("No available hosts to assign Cloudera Manager Service role")

    expected = dict(mgmt_num_descriptor_fetch_tries="15")

    module_args(
        {
            **conn,
            "roles": [
                {
                    "type": "HOSTMONITOR",
                    "cluster_host_id": host.host_id,
                    "config": expected,
                }
            ],
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert len(e.value.service["roles"]) == 1
    assert expected.items() <= e.value.service["roles"][0]["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert len(e.value.service["roles"]) == 1
    assert expected.items() <= e.value.service["roles"][0]["config"].items()


@pytest.mark.role_config(
    dict(mgmt_num_descriptor_fetch_tries=15, process_start_secs=35)
)
def test_existing_role_existing_config_set(
    conn, module_args, cm_api_client, host_monitor_config, request
):
    expected = dict(process_start_secs="35")

    module_args(
        {
            **conn,
            "roles": [
                {
                    "type": "HOSTMONITOR",
                    # "cluster_host_id": host.host_id,
                    "config": {
                        "mgmt_num_descriptor_fetch_tries": None,
                    },
                }
            ],
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert len(e.value.service["roles"]) == 1
    assert expected.items() <= e.value.service["roles"][0]["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert len(e.value.service["roles"]) == 1
    assert expected.items() <= e.value.service["roles"][0]["config"].items()


@pytest.mark.role_config(
    dict(mgmt_num_descriptor_fetch_tries=15, process_start_secs=35)
)
def test_existing_role_existing_config_unset(
    conn, module_args, cm_api_client, host_monitor_config, request
):
    expected = dict(process_start_secs="35")

    module_args(
        {
            **conn,
            "roles": [
                {
                    "type": "HOSTMONITOR",
                    # "cluster_host_id": host.host_id,
                    "config": {
                        "mgmt_num_descriptor_fetch_tries": None,
                    },
                }
            ],
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert len(e.value.service["roles"]) == 1
    assert expected.items() <= e.value.service["roles"][0]["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert len(e.value.service["roles"]) == 1
    assert expected.items() <= e.value.service["roles"][0]["config"].items()


@pytest.mark.role_config(
    dict(mgmt_num_descriptor_fetch_tries=16, process_start_secs=36)
)
def test_existing_role_existing_config_purge(
    conn, module_args, cm_api_client, host_monitor_config, request
):
    expected = dict(process_start_secs="36")

    module_args(
        {
            **conn,
            "roles": [
                {
                    "type": "HOSTMONITOR",
                    # "cluster_host_id": host.host_id,
                    "config": {
                        "process_start_secs": 36,
                    },
                }
            ],
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert len(e.value.service["roles"]) == 1
    assert expected.items() <= e.value.service["roles"][0]["config"].items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert len(e.value.service["roles"]) == 1
    assert expected.items() <= e.value.service["roles"][0]["config"].items()


@pytest.mark.role_config(
    dict(mgmt_num_descriptor_fetch_tries=17, process_start_secs=37)
)
def test_existing_role_existing_config_purge_all(
    conn, module_args, cm_api_client, host_monitor_config, request
):
    module_args(
        {
            **conn,
            "roles": [
                {
                    "type": "HOSTMONITOR",
                    # "cluster_host_id": host.host_id,
                }
            ],
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert len(e.value.service["roles"]) == 1
    assert not e.value.service["roles"][0]["config"]

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert len(e.value.service["roles"]) == 1
    assert not e.value.service["roles"][0]["config"]


def test_existing_role_config_invalid(conn, module_args, cm_api_client, cms, request):
    host_api = HostsResourceApi(cm_api_client)
    host = next((h for h in host_api.read_hosts().items if not h.cluster_ref), None)
    if host is None:
        raise Exception("No available hosts to assign Cloudera Manager Service role")

    expected = dict(mgmt_emit_sensitive_data_in_stderr=True)

    module_args(
        {
            **conn,
            "roles": [
                {
                    "type": "HOSTMONITOR",
                    "cluster_host_id": host.host_id,
                    "config": expected,
                }
            ],
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleFailJson, match="Unknown configuration attribute"):
        cm_service.main()


def test_existing_role_relocate(
    conn, module_args, cm_api_client, host_monitor, request
):
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
            "roles": [
                {
                    "type": "HOSTMONITOR",
                    "cluster_host_id": host.host_id,
                }
            ],
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert len(e.value.service["roles"]) == 1
    assert e.value.service["roles"][0]["host_id"] == host.host_id

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert len(e.value.service["roles"]) == 1
    assert e.value.service["roles"][0]["host_id"] == host.host_id


def test_existing_role_purge(conn, module_args, host_monitor, request):
    module_args(
        {
            **conn,
            "purge": True,
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
            # _ansible_check_mode=True,
            # _ansible_diff=True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == True
    assert not e.value.service["roles"]

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_service.main()

    assert e.value.changed == False
    assert not e.value.service["roles"]
