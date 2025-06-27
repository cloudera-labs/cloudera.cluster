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
    ApiClient,
    ApiHostRef,
    ApiRole,
    ApiService,
)

from ansible_collections.cloudera.cluster.plugins.modules import service_role_info
from ansible_collections.cloudera.cluster.plugins.module_utils.cluster_utils import (
    get_cluster_hosts,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.service_utils import (
    get_service_hosts,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    create_role,
    read_roles,
)
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
    deregister_service,
    register_service,
    deregister_role,
    register_role,
)

LOG = logging.getLogger(__name__)


def gather_server_roles(api_client: ApiClient, service: ApiService):
    return read_roles(
        api_client=api_client,
        cluster_name=service.cluster_ref.cluster_name,
        service_name=service.name,
        type="SERVER",
    ).items


@pytest.fixture(scope="module")
def zookeeper(cm_api_client, base_cluster, request):
    # Keep track of the provisioned service(s)
    service_registry = list[ApiService]()

    # Get the current cluster hosts
    hosts = get_cluster_hosts(cm_api_client, base_cluster)

    id = Path(request.node.parent.name).stem

    zk_service = ApiService(
        name=f"test-zk-{id}",
        type="ZOOKEEPER",
        display_name=f"ZooKeeper ({id})",
        # Add a SERVER role (so we can start the service -- a ZK requirement!)
        roles=[ApiRole(type="SERVER", host_ref=ApiHostRef(hosts[0].host_id))],
    )

    # Provision and yield the created service
    yield register_service(
        api_client=cm_api_client,
        registry=service_registry,
        cluster=base_cluster,
        service=zk_service,
    )

    # Remove the created service
    deregister_service(api_client=cm_api_client, registry=service_registry)


@pytest.fixture()
def server_role(cm_api_client, zookeeper):
    # Keep track of the provisioned role(s)
    role_registry = list[ApiRole]()

    existing_role_instances = [
        r.host_ref.hostname for r in gather_server_roles(cm_api_client, zookeeper)
    ]

    hosts = [
        h
        for h in get_service_hosts(cm_api_client, zookeeper)
        if h.hostname not in existing_role_instances
    ]

    second_role = create_role(
        api_client=cm_api_client,
        role_type="SERVER",
        hostname=hosts[0].hostname,
        cluster_name=zookeeper.cluster_ref.cluster_name,
        service_name=zookeeper.name,
    )

    yield register_role(
        api_client=cm_api_client,
        registry=role_registry,
        service=zookeeper,
        role=second_role,
    )

    deregister_role(api_client=cm_api_client, registry=role_registry)


def test_service_role_info_missing_required(conn, module_args):
    module_args({**conn})

    with pytest.raises(AnsibleFailJson, match="cluster"):
        service_role_info.main()


def test_service_role_info_missing_cluster(conn, module_args):
    module_args(
        {
            **conn,
            "service": "example",
        },
    )

    with pytest.raises(AnsibleFailJson, match="cluster"):
        service_role_info.main()


def test_service_role_info_invalid_service(conn, module_args, zookeeper):
    module_args(
        {
            **conn,
            "cluster": zookeeper.cluster_ref.cluster_name,
            "service": "BOOM",
        },
    )

    with pytest.raises(AnsibleFailJson, match="Service 'BOOM' not found in cluster"):
        service_role_info.main()


def test_service_role_info_invalid_cluster(conn, module_args, zookeeper):
    module_args(
        {
            **conn,
            "cluster": "BOOM",
            "service": zookeeper.name,
        },
    )

    with pytest.raises(AnsibleFailJson, match="Cluster does not exist: BOOM"):
        service_role_info.main()


def test_service_role_info_all(conn, module_args, cm_api_client, zookeeper):
    expected_roles = gather_server_roles(
        api_client=cm_api_client,
        service=zookeeper,
    )

    module_args(
        {
            **conn,
            "cluster": zookeeper.cluster_ref.cluster_name,
            "service": zookeeper.name,
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_info.main()

    assert len(e.value.roles) == len(expected_roles)


def test_service_role_info_all_full(conn, module_args, cm_api_client, zookeeper):
    expected_roles = gather_server_roles(
        api_client=cm_api_client,
        service=zookeeper,
    )

    module_args(
        {
            **conn,
            "cluster": zookeeper.cluster_ref.cluster_name,
            "service": zookeeper.name,
            "view": "full",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_info.main()

    assert len(e.value.roles) == len(expected_roles)


def test_service_role_info_by_name(conn, module_args, cm_api_client, zookeeper):
    expected_roles = gather_server_roles(
        api_client=cm_api_client,
        service=zookeeper,
    )

    module_args(
        {
            **conn,
            "cluster": zookeeper.cluster_ref.cluster_name,
            "service": zookeeper.name,
            "role": expected_roles[0].name,
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_info.main()

    assert len(e.value.roles) == 1
    assert e.value.roles[0]["name"] == expected_roles[0].name


def test_service_role_info_by_type(
    conn,
    module_args,
    cm_api_client,
    zookeeper,
    server_role,
):
    role_type = "SERVER"

    expected_roles = [
        r
        for r in gather_server_roles(
            api_client=cm_api_client,
            service=zookeeper,
        )
        if r.type == role_type
    ]

    module_args(
        {
            **conn,
            "cluster": zookeeper.cluster_ref.cluster_name,
            "service": zookeeper.name,
            "type": role_type,
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_info.main()

    assert len(e.value.roles) == len(expected_roles)


def test_service_role_info_by_hostname(
    conn,
    module_args,
    cm_api_client,
    zookeeper,
    server_role,
):
    expected_roles = gather_server_roles(
        api_client=cm_api_client,
        service=zookeeper,
    )

    module_args(
        {
            **conn,
            "cluster": zookeeper.cluster_ref.cluster_name,
            "service": zookeeper.name,
            "cluster_hostname": expected_roles[0].host_ref.hostname,
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_info.main()

    assert len(e.value.roles) == 1
    assert e.value.roles[0]["host_id"] == expected_roles[0].host_ref.host_id
    assert e.value.roles[0]["hostname"] == expected_roles[0].host_ref.hostname


def test_service_role_info_by_host_id(
    conn,
    module_args,
    cm_api_client,
    zookeeper,
    server_role,
):
    expected_roles = gather_server_roles(
        api_client=cm_api_client,
        service=zookeeper,
    )

    module_args(
        {
            **conn,
            "cluster": zookeeper.cluster_ref.cluster_name,
            "service": zookeeper.name,
            "cluster_host_id": expected_roles[0].host_ref.host_id,
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_info.main()

    assert len(e.value.roles) == 1
    assert e.value.roles[0]["host_id"] == expected_roles[0].host_ref.host_id
    assert e.value.roles[0]["hostname"] == expected_roles[0].host_ref.hostname
