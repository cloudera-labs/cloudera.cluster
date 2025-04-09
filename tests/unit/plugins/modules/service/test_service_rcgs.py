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
    ApiHostRef,
    ApiRole,
    ApiRoleConfigGroup,
    ApiRoleNameList,
    ApiService,
    RoleConfigGroupsResourceApi,
    ServicesResourceApi,
)

from ansible_collections.cloudera.cluster.plugins.modules import service
from ansible_collections.cloudera.cluster.plugins.module_utils.cluster_utils import (
    get_cluster_hosts,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    get_base_role_config_group,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    create_role,
    read_role,
    read_roles,
)
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
    deregister_service,
    register_service,
    deregister_role,
    register_role,
    deregister_role_config_group,
    register_role_config_group,
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


class TestServiceProvisionRoleConfigGroups:
    def test_service_provision_custom_rcg(
        self, conn, module_args, base_cluster, request
    ):
        id = f"pytest-{Path(request.node.name)}"

        module_args(
            {
                **conn,
                "cluster": base_cluster.name,
                "name": id,
                "type": "ZOOKEEPER",
                "role_config_groups": [
                    {
                        "name": id,
                        "type": "SERVER",
                        "config": {
                            "minSessionTimeout": 4601,
                        },
                    }
                ],
                "state": "present",
            }
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
        assert e.value.service["roles"] == list()

        assert len(e.value.service["role_config_groups"]) == 3  # custom + 2 bases
        rcg = next(
            iter([r for r in e.value.service["role_config_groups"] if not r["base"]])
        )
        assert rcg["name"] == id
        assert rcg["role_type"] == "SERVER"
        assert rcg["config"]["minSessionTimeout"] == "4601"

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
        assert e.value.service["roles"] == list()

        assert len(e.value.service["role_config_groups"]) == 3
        rcg = next(
            iter([r for r in e.value.service["role_config_groups"] if not r["base"]])
        )
        assert rcg["name"] == id
        assert rcg["role_type"] == "SERVER"
        assert rcg["config"]["minSessionTimeout"] == "4601"

    def test_service_provision_base_rcg(self, conn, module_args, base_cluster, request):
        id = f"pytest-{Path(request.node.name)}"

        module_args(
            {
                **conn,
                "cluster": base_cluster.name,
                "name": id,
                "type": "ZOOKEEPER",
                "role_config_groups": [
                    {
                        "type": "SERVER",
                        "config": {
                            "minSessionTimeout": 4601,
                        },
                    }
                ],
                "state": "present",
            }
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
        assert e.value.service["roles"] == list()

        assert len(e.value.service["role_config_groups"]) == 2  # 2 bases
        rcg = next(
            iter(
                [
                    r
                    for r in e.value.service["role_config_groups"]
                    if r["base"] and r["role_type"] == "SERVER"
                ]
            )
        )
        assert rcg["role_type"] == "SERVER"
        assert rcg["config"]["minSessionTimeout"] == "4601"

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
        assert e.value.service["roles"] == list()

        assert len(e.value.service["role_config_groups"]) == 2
        rcg = next(
            iter(
                [
                    r
                    for r in e.value.service["role_config_groups"]
                    if r["base"] and r["role_type"] == "SERVER"
                ]
            )
        )
        assert rcg["role_type"] == "SERVER"
        assert rcg["config"]["minSessionTimeout"] == "4601"


class TestServiceModificationRoleConfigGroups:
    @pytest.fixture()
    def base_rcg_server(self, cm_api_client, zookeeper) -> ApiRoleConfigGroup:
        base_rcg = get_base_role_config_group(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_type="SERVER",
        )

        base_rcg.config = ApiConfigList(
            items=[
                ApiConfig(name="minSessionTimeout", value="5500"),
                ApiConfig(name="maxSessionTimeout", value="45000"),
            ]
        )

        return RoleConfigGroupsResourceApi(cm_api_client).update_role_config_group(
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_config_group_name=base_rcg.name,
            body=base_rcg,
        )

    @pytest.fixture()
    def base_rcg_gateway(self, cm_api_client, zookeeper) -> ApiRoleConfigGroup:
        base_rcg = get_base_role_config_group(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_type="GATEWAY",
        )

        base_rcg.config = ApiConfigList(
            items=[ApiConfig(name="client_config_priority", value="91")]
        )

        return RoleConfigGroupsResourceApi(cm_api_client).update_role_config_group(
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_config_group_name=base_rcg.name,
            body=base_rcg,
        )

    @pytest.fixture()
    def custom_rcg_server(
        self, cm_api_client, zookeeper, request
    ) -> Generator[ApiRoleConfigGroup]:
        id = Path(request.node.name).stem

        role_config_groups = list[ApiRoleConfigGroup]()

        yield register_role_config_group(
            api_client=cm_api_client,
            registry=role_config_groups,
            service=zookeeper,
            role_config_group=ApiRoleConfigGroup(
                name=f"pytest-{id}",
                role_type="SERVER",
                config=ApiConfigList(items=[ApiConfig("minSessionTimeout", "4501")]),
                display_name=f"Pytest ({id})",
            ),
            message=f"{Path(request.node.parent.name).stem}::{request.node.name}",
        )

        deregister_role_config_group(
            api_client=cm_api_client,
            registry=role_config_groups,
            message=f"{Path(request.node.parent.name).stem}::{request.node.name}",
        )

    @pytest.fixture()
    def server_role_custom_rcg(
        self, cm_api_client, server_role, custom_rcg_server
    ) -> ApiRole:
        RoleConfigGroupsResourceApi(cm_api_client).move_roles(
            cluster_name=server_role.service_ref.cluster_name,
            service_name=server_role.service_ref.service_name,
            role_config_group_name=custom_rcg_server.name,
            body=ApiRoleNameList(items=[server_role.name]),
        )
        return server_role

    def test_service_existing_base_rcg(
        self, conn, module_args, zookeeper, base_rcg_server, base_rcg_gateway
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "role_config_groups": [
                    {
                        "type": base_rcg_server.role_type,
                        "config": {
                            "minSessionTimeout": 5501,
                            "maxSessionTimeout": 45001,
                        },
                    }
                ],
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True

        server_rcg = next(
            iter(
                [
                    r
                    for r in e.value.service["role_config_groups"]
                    if r["base"] and r["role_type"] == "SERVER"
                ]
            )
        )
        assert server_rcg["config"]["minSessionTimeout"] == "5501"
        assert server_rcg["config"]["maxSessionTimeout"] == "45001"

        gateway_rcg = next(
            iter(
                [
                    r
                    for r in e.value.service["role_config_groups"]
                    if r["base"] and r["role_type"] == "GATEWAY"
                ]
            )
        )
        assert gateway_rcg["config"]["client_config_priority"] == "91"

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False

        server_rcg = next(
            iter(
                [
                    r
                    for r in e.value.service["role_config_groups"]
                    if r["base"] and r["role_type"] == "SERVER"
                ]
            )
        )
        assert server_rcg["config"]["minSessionTimeout"] == "5501"
        assert server_rcg["config"]["maxSessionTimeout"] == "45001"

        gateway_rcg = next(
            iter(
                [
                    r
                    for r in e.value.service["role_config_groups"]
                    if r["base"] and r["role_type"] == "GATEWAY"
                ]
            )
        )
        assert gateway_rcg["config"]["client_config_priority"] == "91"

    def test_service_existing_base_rcg_purge(
        self, conn, module_args, zookeeper, base_rcg_server, base_rcg_gateway
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "role_config_groups": [
                    {
                        "type": base_rcg_server.role_type,
                        "config": {
                            "minSessionTimeout": 5501,
                        },
                    }
                ],
                "purge": True,
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True

        server_rcg = next(
            iter(
                [
                    r
                    for r in e.value.service["role_config_groups"]
                    if r["base"] and r["role_type"] == "SERVER"
                ]
            )
        )
        assert server_rcg["config"]["minSessionTimeout"] == "5501"
        assert "maxSessionTimeout" not in server_rcg["config"]

        gateway_rcg = next(
            iter(
                [
                    r
                    for r in e.value.service["role_config_groups"]
                    if r["base"] and r["role_type"] == "GATEWAY"
                ]
            )
        )
        assert "client_config_priority" not in gateway_rcg["config"]

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False

        server_rcg = next(
            iter(
                [
                    r
                    for r in e.value.service["role_config_groups"]
                    if r["base"] and r["role_type"] == "SERVER"
                ]
            )
        )
        assert server_rcg["config"]["minSessionTimeout"] == "5501"
        assert "maxSessionTimeout" not in server_rcg["config"]

        gateway_rcg = next(
            iter(
                [
                    r
                    for r in e.value.service["role_config_groups"]
                    if r["base"] and r["role_type"] == "GATEWAY"
                ]
            )
        )
        assert "client_config_priority" not in gateway_rcg["config"]

    def test_service_existing_custom_rcg(
        self, conn, module_args, zookeeper, custom_rcg_server
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "role_config_groups": [
                    {
                        "name": custom_rcg_server.name,
                        "config": {
                            "minSessionTimeout": 5501,
                            "maxSessionTimeout": 45001,
                        },
                    }
                ],
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True

        server_rcg = next(
            iter(
                [
                    r
                    for r in e.value.service["role_config_groups"]
                    if r["name"] == custom_rcg_server.name
                ]
            )
        )
        assert server_rcg["config"]["minSessionTimeout"] == "5501"
        assert server_rcg["config"]["maxSessionTimeout"] == "45001"

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False

        server_rcg = next(
            iter(
                [
                    r
                    for r in e.value.service["role_config_groups"]
                    if r["name"] == custom_rcg_server.name
                ]
            )
        )
        assert server_rcg["config"]["minSessionTimeout"] == "5501"
        assert server_rcg["config"]["maxSessionTimeout"] == "45001"

    def test_service_existing_custom_rcg_purge(
        self, conn, module_args, zookeeper, custom_rcg_server
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "role_config_groups": [
                    {
                        "name": custom_rcg_server.name,
                        "config": {
                            "maxSessionTimeout": 45001,
                        },
                    }
                ],
                "purge": True,
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True

        server_rcg = next(
            iter(
                [
                    r
                    for r in e.value.service["role_config_groups"]
                    if r["name"] == custom_rcg_server.name
                ]
            )
        )
        assert server_rcg["config"]["maxSessionTimeout"] == "45001"
        assert "minSessionTimeout" not in server_rcg["config"]

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False

        server_rcg = next(
            iter(
                [
                    r
                    for r in e.value.service["role_config_groups"]
                    if r["name"] == custom_rcg_server.name
                ]
            )
        )
        assert server_rcg["config"]["maxSessionTimeout"] == "45001"
        assert "minSessionTimeout" not in server_rcg["config"]

    def test_service_existing_custom_rcg_purge_role_assoc(
        self, conn, module_args, cm_api_client, zookeeper, server_role_custom_rcg
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "purge": True,
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert server_role_custom_rcg.name not in [
            rcg["name"] for rcg in e.value.service["role_config_groups"]
        ]

        refreshed_role = read_role(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_name=server_role_custom_rcg.name,
        )
        base_rcg = get_base_role_config_group(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_type=server_role_custom_rcg.type,
        )
        assert (
            refreshed_role.role_config_group_ref.role_config_group_name == base_rcg.name
        )

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert server_role_custom_rcg.name not in [
            rcg["name"] for rcg in e.value.service["role_config_groups"]
        ]

        refreshed_role = read_role(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_name=server_role_custom_rcg.name,
        )
        base_rcg = get_base_role_config_group(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_type=server_role_custom_rcg.type,
        )
        assert (
            refreshed_role.role_config_group_ref.role_config_group_name == base_rcg.name
        )
