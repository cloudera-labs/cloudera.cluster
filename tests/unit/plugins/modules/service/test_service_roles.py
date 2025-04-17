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
    ApiCluster,
    ApiEntityTag,
    ApiHost,
    ApiHostRef,
    ApiRole,
    ApiRoleConfigGroup,
    ApiRoleNameList,
    ApiService,
    RoleConfigGroupsResourceApi,
    RolesResourceApi,
    ServicesResourceApi,
)

from ansible_collections.cloudera.cluster.plugins.modules import service
from ansible_collections.cloudera.cluster.plugins.module_utils.cluster_utils import (
    get_cluster_hosts,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    create_role_config_group,
    get_base_role_config_group,
    provision_role_config_groups,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    create_role,
    provision_service_role,
    read_roles,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.service_utils import (
    get_service_hosts,
)
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    deregister_service,
    register_service,
)

LOG = logging.getLogger(__name__)


@pytest.fixture()
def cluster_hosts(cm_api_client, base_cluster) -> list[ApiHost]:
    return get_cluster_hosts(cm_api_client, base_cluster)


class TestServiceProvisionRoles:
    @pytest.fixture(autouse=True)
    def resettable_cluster(self, cm_api_client, base_cluster) -> Generator[ApiCluster]:
        # Keep track of the existing ZOOKEEPER services
        initial_services = set(
            [
                s.name
                for s in ServicesResourceApi(cm_api_client)
                .read_services(
                    cluster_name=base_cluster.name,
                )
                .items
            ]
        )

        # Yield to the test
        yield base_cluster

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

    def test_service_provision_roles(
        self, conn, module_args, cm_api_client, resettable_cluster, request
    ):
        service_name = f"pytest-{Path(request.node.name)}"

        available_hosts = get_cluster_hosts(
            api_client=cm_api_client, cluster=resettable_cluster
        )

        module_args(
            {
                **conn,
                "cluster": resettable_cluster.name,
                "name": service_name,
                "type": "ZOOKEEPER",
                "roles": [
                    {
                        "type": "SERVER",
                        "hostnames": [h.hostname for h in available_hosts],
                    }
                ],
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["name"] == service_name
        assert e.value.service["type"] == "ZOOKEEPER"
        assert e.value.service["display_name"] == service_name
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["roles"]) == len(available_hosts)
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["name"] == service_name
        assert e.value.service["type"] == "ZOOKEEPER"
        assert e.value.service["display_name"] == service_name
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["roles"]) == len(available_hosts)
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases

    def test_service_provision_roles_custom_rcg(
        self, conn, module_args, cm_api_client, resettable_cluster, request
    ):
        service_name = f"pytest-{Path(request.node.name)}"

        available_hosts = get_cluster_hosts(
            api_client=cm_api_client, cluster=resettable_cluster
        )

        module_args(
            {
                **conn,
                "cluster": resettable_cluster.name,
                "name": service_name,
                "type": "ZOOKEEPER",
                "roles": [
                    {
                        "type": "SERVER",
                        "hostnames": [h.hostname for h in available_hosts],
                        "role_config_group": "PYTEST_SERVER",
                    },
                ],
                "role_config_groups": [
                    {
                        "name": "PYTEST_SERVER",
                        "role_type": "SERVER",
                    },
                ],
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["name"] == service_name
        assert e.value.service["type"] == "ZOOKEEPER"
        assert e.value.service["display_name"] == service_name
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["roles"]) == len(available_hosts)
        assert (
            len(e.value.service["role_config_groups"]) == 3
        )  # SERVER, GATEWAY bases + PYTEST_SERVER

        assert e.value.service["roles"][0]["role_config_group_name"] == "PYTEST_SERVER"

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["name"] == service_name
        assert e.value.service["type"] == "ZOOKEEPER"
        assert e.value.service["display_name"] == service_name
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["roles"]) == len(available_hosts)
        assert (
            len(e.value.service["role_config_groups"]) == 3
        )  # SERVER, GATEWAY bases + PYTEST_SERVER

        assert e.value.service["roles"][0]["role_config_group_name"] == "PYTEST_SERVER"

    def test_service_provision_roles_config(
        self, conn, module_args, cm_api_client, resettable_cluster, request
    ):
        service_name = f"pytest-{Path(request.node.name)}"

        available_hosts = get_cluster_hosts(
            api_client=cm_api_client, cluster=resettable_cluster
        )

        module_args(
            {
                **conn,
                "cluster": resettable_cluster.name,
                "name": service_name,
                "type": "ZOOKEEPER",
                "roles": [
                    {
                        "type": "SERVER",
                        "hostnames": [h.hostname for h in available_hosts],
                        "config": {
                            "minSessionTimeout": 4801,
                        },
                    },
                ],
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["name"] == service_name
        assert e.value.service["type"] == "ZOOKEEPER"
        assert e.value.service["display_name"] == service_name
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["roles"]) == len(available_hosts)
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases

        assert e.value.service["roles"][0]["config"]["minSessionTimeout"] == "4801"

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["name"] == service_name
        assert e.value.service["type"] == "ZOOKEEPER"
        assert e.value.service["display_name"] == service_name
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["roles"]) == len(available_hosts)
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases

        assert e.value.service["roles"][0]["config"]["minSessionTimeout"] == "4801"

    def test_service_provision_roles_tags(
        self, conn, module_args, cm_api_client, resettable_cluster, request
    ):
        service_name = f"pytest-{Path(request.node.name)}"

        available_hosts = get_cluster_hosts(
            api_client=cm_api_client, cluster=resettable_cluster
        )

        module_args(
            {
                **conn,
                "cluster": resettable_cluster.name,
                "name": service_name,
                "type": "ZOOKEEPER",
                "roles": [
                    {
                        "type": "SERVER",
                        "hostnames": [h.hostname for h in available_hosts],
                        "tags": {
                            "pytest": "example",
                        },
                    },
                ],
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert e.value.service["name"] == service_name
        assert e.value.service["type"] == "ZOOKEEPER"
        assert e.value.service["display_name"] == service_name
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["roles"]) == len(available_hosts)
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases

        assert e.value.service["roles"][0]["tags"]["pytest"] == "example"

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert e.value.service["name"] == service_name
        assert e.value.service["type"] == "ZOOKEEPER"
        assert e.value.service["display_name"] == service_name
        assert e.value.service["config"] == dict()
        assert e.value.service["tags"] == dict()
        assert e.value.service["maintenance_mode"] == False
        assert len(e.value.service["roles"]) == len(available_hosts)
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases

        assert e.value.service["roles"][0]["tags"]["pytest"] == "example"


class TestServiceModificationRoles:
    @pytest.fixture()
    def zookeeper(self, cm_api_client, base_cluster, request) -> Generator[ApiService]:
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
    def available_hosts(self, cm_api_client, cluster_hosts, zookeeper) -> list[ApiHost]:
        service_host_ids = [
            h.host_id
            for h in get_service_hosts(
                api_client=cm_api_client,
                service=zookeeper,
            )
        ]

        return [h for h in cluster_hosts if h.host_id not in service_host_ids]

    @pytest.fixture()
    def server_role(self, cm_api_client, base_cluster, zookeeper) -> ApiRole:
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

        created_role = create_role(
            api_client=cm_api_client,
            role_type="SERVER",
            hostname=hosts[0].hostname,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
        )

        provisioned_role = provision_service_role(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role=created_role,
        )

        return provisioned_role

    @pytest.fixture()
    def server_rcg(self, cm_api_client, zookeeper, request) -> ApiRoleConfigGroup:
        custom_rcg = create_role_config_group(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            name=f"pytest-{Path(request.node.name).stem}",
            role_type="SERVER",
            config=dict(minSessionTimeout=6601),
        )

        provisioned_rcgs = provision_role_config_groups(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_config_groups=[custom_rcg],
        )

        return provisioned_rcgs.items[0]

    @pytest.fixture()
    def server_rcg_role(self, cm_api_client, server_role, server_rcg) -> ApiRole:
        moved_roles = RoleConfigGroupsResourceApi(cm_api_client).move_roles(
            cluster_name=server_role.service_ref.cluster_name,
            service_name=server_role.service_ref.service_name,
            role_config_group_name=server_rcg.name,
            body=ApiRoleNameList(items=[server_role.name]),
        )

        return moved_roles.items[0]

    def test_service_existing_role_rcg(
        self, conn, module_args, cm_api_client, zookeeper, server_rcg
    ):
        existing_hosts = get_service_hosts(
            api_client=cm_api_client,
            service=zookeeper,
        )

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "roles": [
                    {
                        "type": "SERVER",
                        "hostnames": [h.hostname for h in existing_hosts],
                        "role_config_group": server_rcg.name,
                    }
                ],
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert len(e.value.service["roles"]) == len(existing_hosts)
        assert (
            len(e.value.service["role_config_groups"]) == 3
        )  # SERVER, GATEWAY bases + server_rcg

        assert e.value.service["roles"][0]["role_config_group_name"] == server_rcg.name

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert len(e.value.service["roles"]) == len(existing_hosts)
        assert (
            len(e.value.service["role_config_groups"]) == 3
        )  # SERVER, GATEWAY bases + server_rcg

        assert e.value.service["roles"][0]["role_config_group_name"] == server_rcg.name

    def test_service_existing_role_rcg_base(
        self, conn, module_args, cm_api_client, zookeeper, server_rcg_role
    ):
        base_rcg = get_base_role_config_group(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_type=server_rcg_role.type,
        )

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "roles": [
                    {
                        "type": server_rcg_role.type,
                        "hostnames": [server_rcg_role.host_ref.hostname],
                    }
                ],
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert len(e.value.service["roles"]) == 2  # SERVER + service_rcg_role
        assert (
            len(e.value.service["role_config_groups"]) == 3
        )  # SERVER, GATEWAY bases + server_rcg

        result_role = [
            r
            for r in e.value.service["roles"]
            if r["type"] == server_rcg_role.type
            and r["hostname"] == server_rcg_role.host_ref.hostname
        ][0]
        assert result_role["role_config_group_name"] == base_rcg.name

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert len(e.value.service["roles"]) == 2
        assert (
            len(e.value.service["role_config_groups"]) == 3
        )  # SERVER, GATEWAY bases + server_rcg

        result_role = [
            r
            for r in e.value.service["roles"]
            if r["type"] == server_rcg_role.type
            and r["hostname"] == server_rcg_role.host_ref.hostname
        ][0]
        assert result_role["role_config_group_name"] == base_rcg.name

    def test_service_existing_role_tags(
        self, conn, module_args, cm_api_client, zookeeper, server_role
    ):
        RolesResourceApi(cm_api_client).add_tags(
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_name=server_role.name,
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
                "roles": [
                    {
                        "type": server_role.type,
                        "hostnames": [server_role.host_ref.hostname],
                        "tags": {
                            "tag_one": "Updated",
                            "tag_three": "Added",
                        },
                    }
                ],
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert len(e.value.service["roles"]) == 2  # SERVER + service_role
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases

        result_role = [
            r
            for r in e.value.service["roles"]
            if r["type"] == server_role.type
            and r["hostname"] == server_role.host_ref.hostname
        ][0]
        assert result_role["tags"] == dict(
            tag_one="Updated", tag_two="Existing", tag_three="Added"
        )

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert len(e.value.service["roles"]) == 2  # SERVER + service_role
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases

        result_role = [
            r
            for r in e.value.service["roles"]
            if r["type"] == server_role.type
            and r["hostname"] == server_role.host_ref.hostname
        ][0]
        assert result_role["tags"] == dict(
            tag_one="Updated", tag_two="Existing", tag_three="Added"
        )

    def test_service_existing_role_tags_purge(
        self, conn, module_args, cm_api_client, zookeeper, server_role
    ):
        RolesResourceApi(cm_api_client).add_tags(
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_name=server_role.name,
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
                "roles": [
                    {
                        "type": server_role.type,
                        "hostnames": [server_role.host_ref.hostname],
                        "tags": {
                            "tag_one": "Updated",
                            "tag_three": "Added",
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
        assert len(e.value.service["roles"]) == 1  # service_role
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases

        result_role = [
            r
            for r in e.value.service["roles"]
            if r["type"] == server_role.type
            and r["hostname"] == server_role.host_ref.hostname
        ][0]
        assert result_role["tags"] == dict(tag_one="Updated", tag_three="Added")

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert len(e.value.service["roles"]) == 1  # service_role
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases

        result_role = [
            r
            for r in e.value.service["roles"]
            if r["type"] == server_role.type
            and r["hostname"] == server_role.host_ref.hostname
        ][0]
        assert result_role["tags"] == dict(tag_one="Updated", tag_three="Added")

    def test_service_existing_role_config(
        self, conn, module_args, cm_api_client, zookeeper, server_role
    ):
        RolesResourceApi(cm_api_client).update_role_config(
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_name=server_role.name,
            body=ApiConfigList(
                items=[
                    ApiConfig(name="minSessionTimeout", value="5501"),
                    ApiConfig(name="maxSessionTimeout", value="45001"),
                ]
            ),
        )

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "roles": [
                    {
                        "type": server_role.type,
                        "hostnames": [server_role.host_ref.hostname],
                        "config": {
                            "minSessionTimeout": 5601,
                            "maxClientCnxns": 56,
                        },
                    }
                ],
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert len(e.value.service["roles"]) == 2  # SERVER + service_role
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases

        result_role = [
            r
            for r in e.value.service["roles"]
            if r["type"] == server_role.type
            and r["hostname"] == server_role.host_ref.hostname
        ][0]
        assert (
            result_role["config"].items()
            >= dict(
                minSessionTimeout="5601", maxSessionTimeout="45001", maxClientCnxns="56"
            ).items()
        )

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert len(e.value.service["roles"]) == 2  # SERVER + service_role
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases

        result_role = [
            r
            for r in e.value.service["roles"]
            if r["type"] == server_role.type
            and r["hostname"] == server_role.host_ref.hostname
        ][0]
        assert (
            result_role["config"].items()
            >= dict(
                minSessionTimeout="5601", maxSessionTimeout="45001", maxClientCnxns="56"
            ).items()
        )

    def test_service_existing_role_config_purge(
        self, conn, module_args, cm_api_client, zookeeper, server_role
    ):
        RolesResourceApi(cm_api_client).update_role_config(
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_name=server_role.name,
            body=ApiConfigList(
                items=[
                    ApiConfig(name="minSessionTimeout", value="5501"),
                    ApiConfig(name="maxSessionTimeout", value="45001"),
                ]
            ),
        )

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "roles": [
                    {
                        "type": server_role.type,
                        "hostnames": [server_role.host_ref.hostname],
                        "config": {
                            "minSessionTimeout": 5601,
                            "maxClientCnxns": 56,
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
        assert len(e.value.service["roles"]) == 1  # service_role
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases

        result_role = [
            r
            for r in e.value.service["roles"]
            if r["type"] == server_role.type
            and r["hostname"] == server_role.host_ref.hostname
        ][0]
        assert (
            result_role["config"].items()
            == dict(minSessionTimeout="5601", maxClientCnxns="56").items()
        )

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert len(e.value.service["roles"]) == 1  # service_role
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases

        result_role = [
            r
            for r in e.value.service["roles"]
            if r["type"] == server_role.type
            and r["hostname"] == server_role.host_ref.hostname
        ][0]
        assert (
            result_role["config"].items()
            == dict(minSessionTimeout="5601", maxClientCnxns="56").items()
        )

    def test_service_existing_role_add(
        self, conn, module_args, zookeeper, available_hosts
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "roles": [
                    {
                        "type": "SERVER",
                        "hostnames": [available_hosts[0].hostname],
                    }
                ],
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == True
        assert len(e.value.service["roles"]) == 2  # SERVER + new SERVER
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert available_hosts[0].hostname in [
            r["hostname"] for r in e.value.service["roles"] if r["type"] == "SERVER"
        ]

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert len(e.value.service["roles"]) == 2  # SERVER + new SERVER
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert available_hosts[0].hostname in [
            r["hostname"] for r in e.value.service["roles"] if r["type"] == "SERVER"
        ]

    def test_service_existing_role_purge(
        self, conn, module_args, zookeeper, available_hosts
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "name": zookeeper.name,
                "roles": [
                    {
                        "type": "SERVER",
                        "hostnames": [available_hosts[0].hostname],
                        "config": {
                            "serverId": 9,
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
        assert len(e.value.service["roles"]) == 1  # new SERVER
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert available_hosts[0].hostname in [
            r["hostname"] for r in e.value.service["roles"] if r["type"] == "SERVER"
        ]

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service.main()

        assert e.value.changed == False
        assert len(e.value.service["roles"]) == 1  # new SERVER
        assert len(e.value.service["role_config_groups"]) == 2  # SERVER, GATEWAY bases
        assert available_hosts[0].hostname in [
            r["hostname"] for r in e.value.service["roles"] if r["type"] == "SERVER"
        ]
