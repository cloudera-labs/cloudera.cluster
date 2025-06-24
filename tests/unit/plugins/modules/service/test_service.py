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
    ApiEntityTag,
    ApiHostRef,
    ApiRole,
    ApiService,
    ApiServiceConfig,
    ApiServiceState,
    ServicesResourceApi,
)

from ansible_collections.cloudera.cluster.plugins.modules import service
from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    wait_command,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.cluster_utils import (
    get_cluster_hosts,
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


@pytest.fixture()
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
def server_role(cm_api_client, base_cluster, zookeeper):
    # Keep track of the provisioned role(s)
    role_registry = list[ApiRole]()

    existing_role_instances = [
        r.host_ref.hostname
        for r in read_roles(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            type="SERVER",
        ).items
    ]

    hosts = [
        h
        for h in get_cluster_hosts(cm_api_client, base_cluster)
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


class TestServiceArgSpec:
    def test_service_missing_required(self, conn, module_args):
        module_args(conn)

        with pytest.raises(AnsibleFailJson, match="cluster, name"):
            service.main()

    def test_service_missing_name(self, conn, module_args):
        module_args(
            {
                **conn,
                "service": "example",
            },
        )

        with pytest.raises(AnsibleFailJson, match="cluster"):
            service.main()

    def test_service_missing_cluster(self, conn, module_args):
        module_args(
            {
                **conn,
                "cluster": "example",
            },
        )

        with pytest.raises(AnsibleFailJson, match="name"):
            service.main()

    def test_service_roles_missing_type(self, conn, module_args):
        module_args(
            {
                **conn,
                "cluster": "example",
                "name": "example",
                "roles": [
                    {
                        "hostnames": "example",
                    },
                ],
            },
        )

        with pytest.raises(AnsibleFailJson, match="type found in roles"):
            service.main()

    def test_service_roles_missing_hostnames(self, conn, module_args):
        module_args(
            {
                **conn,
                "cluster": "example",
                "name": "example",
                "roles": [
                    {
                        "type": "example",
                    },
                ],
            },
        )

        with pytest.raises(AnsibleFailJson, match="hostnames found in roles"):
            service.main()


class TestServiceInvalidParameters:
    def test_present_invalid_cluster(self, conn, module_args):
        module_args({**conn, "cluster": "BOOM", "service": "example"})

        with pytest.raises(AnsibleFailJson, match="Cluster does not exist"):
            service.main()

    def test_present_missing_type(self, conn, module_args, base_cluster):
        module_args(
            {
                **conn,
                "cluster": base_cluster.name,
                "service": "test-zookeeper",
            },
        )

        with pytest.raises(AnsibleFailJson, match="type"):
            service.main()


class TestServiceProvision:
    @pytest.fixture(autouse=True)
    def zookeeper_reset(self, cm_api_client, base_cluster):
        # Keep track of the existing ZOOKEEPER services
        initial_services = set(
            [
                s.name
                for s in ServicesResourceApi(cm_api_client)
                .read_services(
                    cluster_name=base_cluster.name,
                )
                .items
            ],
        )

        # Yield to the test
        yield

        # Remove any added services
        services_to_remove = [
            s
            for s in ServicesResourceApi(cm_api_client)
            .read_services(
                cluster_name=base_cluster.name,
            )
            .items
            if s.name not in initial_services
        ]
        deregister_service(cm_api_client, services_to_remove)

    def test_service_provision_core(self, conn, module_args, base_cluster, request):
        id = f"pytest-{Path(request.node.name)}"

        module_args(
            {
                **conn,
                "cluster": base_cluster.name,
                "name": id,
                "type": "ZOOKEEPER",
                "state": "present",
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["name"] == id
        assert e.value.service["type"] == "ZOOKEEPER"
        assert e.value.service["display_name"] == id
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert e.value.service["roles"] == list()

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["name"] == id
        assert e.value.service["type"] == "ZOOKEEPER"
        assert e.value.service["display_name"] == id
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert e.value.service["roles"] == list()

    def test_service_provision_display_name(
        self,
        conn,
        module_args,
        base_cluster,
        request,
    ):
        id = f"pytest-{Path(request.node.name)}"
        name = "Pytest ZooKeeper"

        module_args(
            {
                **conn,
                "cluster": base_cluster.name,
                "name": id,
                "type": "ZOOKEEPER",
                "display_name": name,
                "state": "present",
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["name"] == id
        assert e.value.service["type"] == "ZOOKEEPER"
        assert e.value.service["display_name"] == name
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert e.value.service["roles"] == list()

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["name"] == id
        assert e.value.service["type"] == "ZOOKEEPER"
        assert e.value.service["display_name"] == name
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert e.value.service["roles"] == list()

    def test_service_provision_config(self, conn, module_args, base_cluster, request):
        id = f"pytest-{Path(request.node.name)}"

        module_args(
            {
                **conn,
                "cluster": base_cluster.name,
                "name": id,
                "type": "ZOOKEEPER",
                "config": {"tickTime": 2001},
                "state": "present",
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["name"] == id
        assert e.value.service["type"] == "ZOOKEEPER"
        assert e.value.service["display_name"] == id
        assert e.value.service["config"]["tickTime"] == "2001"
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert e.value.service["roles"] == list()

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["name"] == id
        assert e.value.service["type"] == "ZOOKEEPER"
        assert e.value.service["display_name"] == id
        assert e.value.service["config"]["tickTime"] == "2001"
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert e.value.service["roles"] == list()

    def test_service_provision_tags(self, conn, module_args, base_cluster, request):
        id = f"pytest-{Path(request.node.name)}"

        module_args(
            {
                **conn,
                "cluster": base_cluster.name,
                "name": id,
                "type": "ZOOKEEPER",
                "tags": {"pytest": "example"},
                "state": "present",
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["name"] == id
        assert e.value.service["type"] == "ZOOKEEPER"
        assert e.value.service["display_name"] == id
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"]["pytest"] == "example"
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert e.value.service["roles"] == list()

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["name"] == id
        assert e.value.service["type"] == "ZOOKEEPER"
        assert e.value.service["display_name"] == id
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"]["pytest"] == "example"
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert e.value.service["roles"] == list()


class TestServiceModification:
    @pytest.fixture()
    def maintenance_enabled_zookeeper(self, cm_api_client, zookeeper) -> ApiService:
        ServicesResourceApi(cm_api_client).enter_maintenance_mode(
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
        )
        return zookeeper

    def test_service_existing_type(self, conn, module_args, zookeeper):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "type": "GATEWAY",
                "state": "present",
            },
        )

        with pytest.raises(AnsibleFailJson, match="already in use"):
            service.main()

    def test_service_existing_display_name(self, conn, module_args, zookeeper):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "display_name": "Example",
                "state": "present",
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["name"] == zookeeper.name
        assert e.value.service["type"] == zookeeper.type
        assert e.value.service["display_name"] == "Example"
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert len(e.value.service["roles"]) == 1  # SERVER

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["name"] == zookeeper.name
        assert e.value.service["type"] == zookeeper.type
        assert e.value.service["display_name"] == "Example"
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert len(e.value.service["roles"]) == 1  # SERVER

    def test_service_existing_maintenance_enabled(self, conn, module_args, zookeeper):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "maintenance": True,
                "state": "present",
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["name"] == zookeeper.name
        assert e.value.service["type"] == zookeeper.type
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == True
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert len(e.value.service["roles"]) == 1  # SERVER

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["name"] == zookeeper.name
        assert e.value.service["type"] == zookeeper.type
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == True
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert len(e.value.service["roles"]) == 1  # SERVER

    def test_service_existing_maintenance_disabled(
        self,
        conn,
        module_args,
        cm_api_client,
        zookeeper,
    ):
        ServicesResourceApi(cm_api_client).enter_maintenance_mode(
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
        )

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "maintenance": False,
                "state": "present",
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["name"] == zookeeper.name
        assert e.value.service["type"] == zookeeper.type
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert len(e.value.service["roles"]) == 1  # SERVER

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["name"] == zookeeper.name
        assert e.value.service["type"] == zookeeper.type
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert len(e.value.service["roles"]) == 1  # SERVER

    def test_service_existing_config(
        self,
        conn,
        module_args,
        cm_api_client,
        zookeeper,
        request,
    ):
        ServicesResourceApi(cm_api_client).update_service_config(
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            message=f"{request.node.name}::set",
            body=ApiServiceConfig(
                items=[
                    ApiConfig(name="tickTime", value="3001"),
                    ApiConfig(name="autopurgeSnapRetainCount", value="9"),
                ],
            ),
        )

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "config": {
                    "tickTime": 2001,
                    "leaderServes": "no",
                },
                "message": f"{request.node.name}::test",
                "state": "present",
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["name"] == zookeeper.name
        assert e.value.service["type"] == zookeeper.type
        assert e.value.service["config"] == dict(
            tickTime="2001",
            leaderServes="no",
            autopurgeSnapRetainCount="9",
        )
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert len(e.value.service["roles"]) == 1  # SERVER

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["name"] == zookeeper.name
        assert e.value.service["type"] == zookeeper.type
        assert e.value.service["config"] == dict(
            tickTime="2001",
            leaderServes="no",
            autopurgeSnapRetainCount="9",
        )
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert len(e.value.service["roles"]) == 1  # SERVER

    def test_service_existing_config_purge(
        self,
        conn,
        module_args,
        cm_api_client,
        zookeeper,
        request,
    ):
        ServicesResourceApi(cm_api_client).update_service_config(
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            message=f"{request.node.name}::set",
            body=ApiServiceConfig(
                items=[
                    ApiConfig(name="tickTime", value="3001"),
                    ApiConfig(name="autopurgeSnapRetainCount", value="9"),
                ],
            ),
        )

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "config": {
                    "tickTime": 2001,
                    "leaderServes": "no",
                },
                "message": f"{request.node.name}::test",
                "purge": True,
                "state": "present",
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["name"] == zookeeper.name
        assert e.value.service["type"] == zookeeper.type
        assert e.value.service["config"] == dict(
            tickTime="2001",
            leaderServes="no",
        )
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert len(e.value.service["roles"]) == 1  # SERVER

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["name"] == zookeeper.name
        assert e.value.service["type"] == zookeeper.type
        assert e.value.service["config"] == dict(tickTime="2001", leaderServes="no")
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert len(e.value.service["roles"]) == 1  # SERVER

    def test_service_existing_tags(self, conn, module_args, cm_api_client, zookeeper):
        ServicesResourceApi(cm_api_client).add_tags(
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            body=[
                ApiEntityTag(name="tag_one", value="Existing"),
                ApiEntityTag(name="tag_two", value="Existing"),
            ],
        )

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "tags": {
                    "tag_one": "Updated",
                    "tag_three": "Added",
                },
                "state": "present",
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["name"] == zookeeper.name
        assert e.value.service["type"] == zookeeper.type
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict(
            tag_one="Updated",
            tag_two="Existing",
            tag_three="Added",
        )
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert len(e.value.service["roles"]) == 1  # SERVER

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["name"] == zookeeper.name
        assert e.value.service["type"] == zookeeper.type
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict(
            tag_one="Updated",
            tag_two="Existing",
            tag_three="Added",
        )
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert len(e.value.service["roles"]) == 1  # SERVER

    def test_service_existing_tags_purge(
        self,
        conn,
        module_args,
        cm_api_client,
        zookeeper,
    ):
        ServicesResourceApi(cm_api_client).add_tags(
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            body=[
                ApiEntityTag(name="tag_one", value="Existing"),
                ApiEntityTag(name="tag_two", value="Existing"),
            ],
        )

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "tags": {
                    "tag_one": "Updated",
                    "tag_three": "Added",
                },
                "purge": True,
                "state": "present",
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["name"] == zookeeper.name
        assert e.value.service["type"] == zookeeper.type
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict(tag_one="Updated", tag_three="Added")
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert len(e.value.service["roles"]) == 1  # SERVER

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["name"] == zookeeper.name
        assert e.value.service["type"] == zookeeper.type
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict(tag_one="Updated", tag_three="Added")
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert len(e.value.service["roles"]) == 1  # SERVER


class TestServiceStates:
    def test_service_existing_state_started(
        self,
        conn,
        module_args,
        cm_api_client,
        zookeeper,
    ):
        if zookeeper.service_state not in [
            ApiServiceState.STOPPED,
            ApiServiceState.STOPPING,
        ]:
            stop_cmd = ServicesResourceApi(cm_api_client).stop_command(
                cluster_name=zookeeper.cluster_ref.cluster_name,
                service_name=zookeeper.name,
            )

            wait_command(cm_api_client, stop_cmd)

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "state": "started",
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["service_state"] == ApiServiceState.STARTED

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["service_state"] == ApiServiceState.STARTED

    def test_service_existing_state_stopped(
        self,
        conn,
        module_args,
        cm_api_client,
        zookeeper,
    ):
        if zookeeper.service_state not in [
            ApiServiceState.STARTED,
            ApiServiceState.STARTING,
        ]:
            start_cmd = ServicesResourceApi(cm_api_client).start_command(
                cluster_name=zookeeper.cluster_ref.cluster_name,
                service_name=zookeeper.name,
            )

            wait_command(cm_api_client, start_cmd)

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "state": "stopped",
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["service_state"] == ApiServiceState.STOPPED

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["service_state"] == ApiServiceState.STOPPED

    def test_service_existing_state_restarted(
        self,
        conn,
        module_args,
        cm_api_client,
        zookeeper,
    ):
        if zookeeper.service_state not in [
            ApiServiceState.STARTED,
            ApiServiceState.STARTING,
        ]:
            start_cmd = ServicesResourceApi(cm_api_client).start_command(
                cluster_name=zookeeper.cluster_ref.cluster_name,
                service_name=zookeeper.name,
            )

            wait_command(cm_api_client, start_cmd)

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "state": "restarted",
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["service_state"] == ApiServiceState.STARTED

        # No idempotency due to the nature of the state
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["service_state"] == ApiServiceState.STARTED

    def test_service_existing_state_absent(
        self,
        conn,
        module_args,
        cm_api_client,
        zookeeper,
    ):
        if zookeeper.service_state not in [
            ApiServiceState.STARTED,
            ApiServiceState.STARTING,
        ]:
            start_cmd = ServicesResourceApi(cm_api_client).start_command(
                cluster_name=zookeeper.cluster_ref.cluster_name,
                service_name=zookeeper.name,
            )

            wait_command(cm_api_client, start_cmd)

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "state": "absent",
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert not e.value.service

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert not e.value.service
