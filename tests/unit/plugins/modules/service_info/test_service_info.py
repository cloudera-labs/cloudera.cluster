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
    ApiHost,
    ApiHostRef,
    ApiRole,
    ApiService,
)

from ansible_collections.cloudera.cluster.plugins.modules import service_info

from ansible_collections.cloudera.cluster.plugins.module_utils.cluster_utils import (
    get_cluster_hosts,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.service_utils import (
    get_service_hosts,
)
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
    deregister_service,
    register_service,
)

LOG = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def zookeeper(cm_api_client, base_cluster, request):
    # Keep track of the provisioned service(s)
    service_registry = list[ApiService]()

    # Get the current cluster hosts
    hosts = get_cluster_hosts(cm_api_client, base_cluster)

    id = Path(request.node.name).stem

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
def cluster_hosts(cm_api_client, base_cluster) -> list[ApiHost]:
    return get_cluster_hosts(cm_api_client, base_cluster)


@pytest.fixture()
def available_hosts(cm_api_client, cluster_hosts, zookeeper) -> list[ApiHost]:
    service_host_ids = [
        h.host_id
        for h in get_service_hosts(
            api_client=cm_api_client,
            service=zookeeper,
        )
    ]

    return [h for h in cluster_hosts if h.host_id not in service_host_ids]


def test_missing_required(conn, module_args):
    module_args(
        {
            **conn,
        }
    )

    with pytest.raises(AnsibleFailJson, match="cluster"):
        service_info.main()


def test_missing_cluster(conn, module_args):
    module_args(
        {
            **conn,
            "service": "example",
        }
    )

    with pytest.raises(AnsibleFailJson, match="cluster"):
        service_info.main()


def test_invalid_cluster(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": "invalid",
            "service": "example",
        }
    )

    with pytest.raises(AnsibleFailJson, match="Cluster does not exist") as e:
        service_info.main()


def test_invalid_service(conn, module_args, base_cluster):
    module_args(
        {
            **conn,
            "cluster": base_cluster.name,
            "service": "not_found",
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_info.main()

    assert len(e.value.services) == 0


def test_all_services(
    conn,
    module_args,
    request,
    base_cluster,
    zookeeper,
    available_hosts,
    service_factory,
):
    id = Path(request.node.name)

    # Add an additional ZooKeeper service
    zookeeper_two = service_factory(
        cluster=base_cluster,
        service=ApiService(
            name=f"test-zk-{id}",
            type="ZOOKEEPER",
            display_name=f"ZooKeeper ({id})",
            # Add a SERVER role (so we can start the service -- a ZK requirement!)
            roles=[
                ApiRole(type="SERVER", host_ref=ApiHostRef(available_hosts[0].host_id))
            ],
        ),
    )

    module_args(
        {
            **conn,
            "cluster": zookeeper.cluster_ref.cluster_name,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_info.main()

    assert len(e.value.services) == 3  # 2 ZK and 1 core settings
    service_names = [s["name"] for s in e.value.services]
    assert zookeeper.name in service_names
    assert zookeeper_two.name in service_names


def test_named_service(conn, module_args, zookeeper):
    module_args(
        {
            **conn,
            "cluster": zookeeper.cluster_ref.cluster_name,
            "service": zookeeper.name,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_info.main()

    assert len(e.value.services) == 1  # Single named ZK
    service_names = [s["name"] for s in e.value.services]
    assert zookeeper.name in service_names
