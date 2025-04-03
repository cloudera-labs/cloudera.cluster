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
    ApiConfig,
    ApiConfigList,
    ApiEntityTag,
    ApiHostRef,
    ApiRole,
    ApiRoleConfigGroup,
    ApiRoleNameList,
    ApiRoleState,
    ApiService,
    RoleConfigGroupsResourceApi,
    RolesResourceApi,
    RoleCommandsResourceApi,
)

from ansible.module_utils.common.dict_transformations import recursive_diff

from ansible_collections.cloudera.cluster.plugins.modules import service_role
from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    wait_bulk_commands,
)
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
    deregister_role_config_group,
    register_role_config_group,
)

LOG = logging.getLogger(__name__)


def gather_server_roles(api_client: ApiClient, service: ApiService) -> list[ApiRole]:
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


@pytest.fixture()
def server_role_reset(cm_api_client, zookeeper):
    # Keep track of the existing SERVER roles
    initial_roles = set([r.name for r in gather_server_roles(cm_api_client, zookeeper)])

    # Yield to the test
    yield

    # Remove any added roles
    roles_to_remove = [
        r
        for r in gather_server_roles(cm_api_client, zookeeper)
        if r.name not in initial_roles
    ]
    deregister_role(cm_api_client, roles_to_remove)


class TestServiceRoleArgSpec:
    def test_service_role_missing_required(self, conn, module_args):
        module_args(conn)

        with pytest.raises(AnsibleFailJson, match="cluster, service"):
            service_role.main()

    def test_service_role_missing_one_of(self, conn, module_args):
        module_args(
            {
                **conn,
                "cluster": "cluster",
                "service": "service",
            }
        )

        with pytest.raises(AnsibleFailJson, match="type, name"):
            service_role.main()

    def test_service_role_missing_required_by_type(self, conn, module_args):
        module_args(
            {
                **conn,
                "cluster": "cluster",
                "service": "service",
                "type": "type",
            }
        )

        with pytest.raises(AnsibleFailJson, match="cluster_hostname, cluster_host_id"):
            service_role.main()

    def test_service_role_missing_required_by_type_exclusives(self, conn, module_args):
        module_args(
            {
                **conn,
                "cluster": "cluster",
                "service": "service",
                "type": "type",
                "cluster_hostname": "hostname",
                "cluster_host_id": "host_id",
            }
        )

        with pytest.raises(
            AnsibleFailJson,
            match="mutually exclusive: cluster_hostname\|cluster_host_id",
        ):
            service_role.main()


class TestServiceRoleInvalidParams:
    def test_service_role_invalid_cluster(self, conn, module_args):
        module_args(
            {
                **conn,
                "cluster": "example",
                "service": "example",
                "type": "type",
                "cluster_hostname": "hostname",
            }
        )

        with pytest.raises(AnsibleFailJson, match="Cluster does not exist"):
            service_role.main()

    def test_service_role_invalid_service(
        self, conn, module_args, cm_api_client, zookeeper
    ):
        expected_roles = gather_server_roles(
            api_client=cm_api_client,
            service=zookeeper,
        )

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": "example",
                "type": expected_roles[0].type,
                "cluster_hostname": expected_roles[0].host_ref.hostname,
            }
        )

        with pytest.raises(AnsibleFailJson, match="Service does not exist"):
            service_role.main()

    def test_service_role_invalid_type(
        self, conn, module_args, cm_api_client, zookeeper
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
                "type": "example",
                "cluster_hostname": expected_roles[0].host_ref.hostname,
            }
        )

        with pytest.raises(
            AnsibleFailJson,
            match="Base role config group of type EXAMPLE not found in service",
        ):
            service_role.main()

    def test_service_role_invalid_host(
        self, conn, module_args, cm_api_client, zookeeper
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
                "type": expected_roles[0].type,
                "cluster_hostname": "example",
            }
        )

        with pytest.raises(AnsibleFailJson, match="Host not found"):
            service_role.main()

    def test_service_role_invalid_role_name(self, conn, module_args, zookeeper):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "name": "example",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert not e.value.role


class TestServiceRoleProvision:
    def test_service_role_provision_hostname(
        self, conn, module_args, cm_api_client, zookeeper, server_role_reset
    ):
        existing_role_instances = [
            r.host_ref.hostname
            for r in gather_server_roles(
                api_client=cm_api_client,
                service=zookeeper,
            )
        ]

        hosts = [
            h
            for h in get_service_hosts(cm_api_client, zookeeper)
            if h.hostname not in existing_role_instances
        ]

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "type": "SERVER",
                "cluster_hostname": hosts[0].hostname,
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.role["type"] == "SERVER"
        assert e.value.role["hostname"] == hosts[0].hostname
        assert e.value.role["role_state"] == ApiRoleState.STOPPED

    def test_service_role_provision_host_id(
        self, conn, module_args, cm_api_client, zookeeper, server_role_reset
    ):
        existing_role_instances = [
            r.host_ref.hostname
            for r in gather_server_roles(
                api_client=cm_api_client,
                service=zookeeper,
            )
        ]

        hosts = [
            h
            for h in get_service_hosts(cm_api_client, zookeeper)
            if h.hostname not in existing_role_instances
        ]

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "type": "SERVER",
                "cluster_host_id": hosts[0].host_id,
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.role["type"] == "SERVER"
        assert e.value.role["host_id"] == hosts[0].host_id
        assert e.value.role["role_state"] == ApiRoleState.STOPPED

    def test_service_role_provision_config(
        self, conn, module_args, cm_api_client, zookeeper, server_role_reset
    ):
        existing_role_instances = [
            r.host_ref.hostname
            for r in gather_server_roles(
                api_client=cm_api_client,
                service=zookeeper,
            )
        ]

        hosts = [
            h
            for h in get_service_hosts(cm_api_client, zookeeper)
            if h.hostname not in existing_role_instances
        ]

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "type": "SERVER",
                "cluster_hostname": hosts[0].hostname,
                "config": {
                    "minSessionTimeout": 4500,
                },
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.role["type"] == "SERVER"
        assert e.value.role["hostname"] == hosts[0].hostname
        assert e.value.role["role_state"] == ApiRoleState.STOPPED
        assert e.value.role["config"]["minSessionTimeout"] == "4500"

    def test_service_role_provision_role_config_group(
        self,
        conn,
        module_args,
        cm_api_client,
        zookeeper,
        role_config_group_factory,
        server_role_reset,
        request,
    ):
        id = Path(request.node.parent.name).stem

        rcg = role_config_group_factory(
            service=zookeeper,
            role_config_group=ApiRoleConfigGroup(
                name=f"pytest-{id}",
                role_type="SERVER",
                config=ApiConfigList(items=[ApiConfig("minSessionTimeout", "4501")]),
                display_name=f"Pytest ({id})",
            ),
        )

        existing_role_instances = [
            r.host_ref.hostname
            for r in gather_server_roles(
                api_client=cm_api_client,
                service=zookeeper,
            )
        ]

        hosts = [
            h
            for h in get_service_hosts(cm_api_client, zookeeper)
            if h.hostname not in existing_role_instances
        ]

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "type": rcg.role_type,
                "cluster_hostname": hosts[0].hostname,
                "role_config_group": rcg.name,
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.role["type"] == "SERVER"
        assert e.value.role["hostname"] == hosts[0].hostname
        assert e.value.role["role_state"] == ApiRoleState.STOPPED
        assert e.value.role["role_config_group_name"] == rcg.name
        assert e.value.role["config"]["minSessionTimeout"] == "4501"

    def test_service_role_provision_tags(
        self, conn, module_args, cm_api_client, zookeeper, server_role_reset
    ):
        existing_role_instances = [
            r.host_ref.hostname
            for r in gather_server_roles(
                api_client=cm_api_client,
                service=zookeeper,
            )
        ]

        hosts = [
            h
            for h in get_service_hosts(cm_api_client, zookeeper)
            if h.hostname not in existing_role_instances
        ]

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "type": "SERVER",
                "cluster_hostname": hosts[0].hostname,
                "tags": {
                    "pytest": "success",
                },
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.role["type"] == "SERVER"
        assert e.value.role["hostname"] == hosts[0].hostname
        assert e.value.role["role_state"] == ApiRoleState.STOPPED
        assert e.value.role["tags"]["pytest"] == "success"

    def test_service_role_provision_enable_maintenance(
        self, conn, module_args, cm_api_client, zookeeper, server_role_reset
    ):
        existing_role_instances = [
            r.host_ref.hostname
            for r in gather_server_roles(
                api_client=cm_api_client,
                service=zookeeper,
            )
        ]

        hosts = [
            h
            for h in get_service_hosts(cm_api_client, zookeeper)
            if h.hostname not in existing_role_instances
        ]

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "type": "SERVER",
                "cluster_hostname": hosts[0].hostname,
                "maintenance": True,
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.role["type"] == "SERVER"
        assert e.value.role["hostname"] == hosts[0].hostname
        assert e.value.role["role_state"] == ApiRoleState.STOPPED
        assert e.value.role["maintenance_mode"] == True

    def test_service_role_provision_state_start(
        self, conn, module_args, cm_api_client, zookeeper, server_role_reset
    ):
        existing_role_instances = [
            r.host_ref.hostname
            for r in gather_server_roles(
                api_client=cm_api_client,
                service=zookeeper,
            )
        ]

        hosts = [
            h
            for h in get_service_hosts(cm_api_client, zookeeper)
            if h.hostname not in existing_role_instances
        ]

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "type": "SERVER",
                "cluster_hostname": hosts[0].hostname,
                "state": "started",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.role["type"] == "SERVER"
        assert e.value.role["hostname"] == hosts[0].hostname
        assert e.value.role["role_state"] == ApiRoleState.STARTED

    def test_service_role_provision_state_stopped(
        self, conn, module_args, cm_api_client, zookeeper, server_role_reset
    ):
        existing_role_instances = [
            r.host_ref.hostname
            for r in gather_server_roles(
                api_client=cm_api_client,
                service=zookeeper,
            )
        ]

        hosts = [
            h
            for h in get_service_hosts(cm_api_client, zookeeper)
            if h.hostname not in existing_role_instances
        ]

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "type": "SERVER",
                "cluster_hostname": hosts[0].hostname,
                "state": "stopped",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.role["type"] == "SERVER"
        assert e.value.role["hostname"] == hosts[0].hostname
        assert e.value.role["role_state"] == ApiRoleState.STOPPED

    def test_service_role_provision_state_restarted(
        self, conn, module_args, cm_api_client, zookeeper, server_role_reset
    ):
        existing_role_instances = [
            r.host_ref.hostname
            for r in gather_server_roles(
                api_client=cm_api_client,
                service=zookeeper,
            )
        ]

        hosts = [
            h
            for h in get_service_hosts(cm_api_client, zookeeper)
            if h.hostname not in existing_role_instances
        ]

        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "type": "SERVER",
                "cluster_hostname": hosts[0].hostname,
                "state": "restarted",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.role["type"] == "SERVER"
        assert e.value.role["hostname"] == hosts[0].hostname
        assert e.value.role["role_state"] == ApiRoleState.STARTED


class TestServiceRoleModification:
    @pytest.fixture()
    def updated_server_role_config(self, cm_api_client, server_role):
        RolesResourceApi(cm_api_client).update_role_config(
            cluster_name=server_role.service_ref.cluster_name,
            service_name=server_role.service_ref.service_name,
            role_name=server_role.name,
            body=ApiConfigList(
                items=[
                    ApiConfig(
                        "minSessionTimeout",
                        5000,
                    )
                ]
            ),
        )
        return server_role

    @pytest.fixture()
    def updated_server_role_tags(self, cm_api_client, server_role):
        RolesResourceApi(cm_api_client).add_tags(
            cluster_name=server_role.service_ref.cluster_name,
            service_name=server_role.service_ref.service_name,
            role_name=server_role.name,
            body=[ApiEntityTag("existing", "tag")],
        )
        return server_role

    @pytest.fixture()
    def stopped_server_role(self, cm_api_client, server_role):
        stop_cmds = RoleCommandsResourceApi(cm_api_client).stop_command(
            cluster_name=server_role.service_ref.cluster_name,
            service_name=server_role.service_ref.service_name,
            body=ApiRoleNameList(items=[server_role.name]),
        )
        wait_bulk_commands(
            api_client=cm_api_client,
            commands=stop_cmds,
        )
        return server_role

    @pytest.fixture()
    def custom_rcg_server_role(self, cm_api_client, zookeeper, request):
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
    def updated_server_role_rcg(
        self, cm_api_client, server_role, custom_rcg_server_role
    ):
        RoleConfigGroupsResourceApi(cm_api_client).move_roles(
            cluster_name=server_role.service_ref.cluster_name,
            service_name=server_role.service_ref.service_name,
            role_config_group_name=custom_rcg_server_role.name,
            body=ApiRoleNameList(items=[server_role.name]),
        )
        return server_role

    def test_service_role_existing_name(
        self, conn, module_args, zookeeper, server_role
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "name": server_role.name,
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == False
        assert e.value.role["type"] == server_role.type
        assert e.value.role["hostname"] == server_role.host_ref.hostname
        assert e.value.role["role_state"] == ApiRoleState.STARTED

    def test_service_role_existing_hostname(
        self, conn, module_args, zookeeper, server_role
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "type": server_role.type,
                "cluster_hostname": server_role.host_ref.hostname,
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == False
        assert e.value.role["type"] == server_role.type
        assert e.value.role["hostname"] == server_role.host_ref.hostname
        assert e.value.role["role_state"] == ApiRoleState.STARTED

    def test_service_role_existing_hostid(
        self, conn, module_args, zookeeper, server_role
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "type": server_role.type,
                "cluster_host_id": server_role.host_ref.host_id,
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == False
        assert e.value.role["type"] == server_role.type
        assert e.value.role["hostname"] == server_role.host_ref.hostname
        assert e.value.role["role_state"] == ApiRoleState.STARTED

    def test_service_role_existing_enable_maintenance(
        self, conn, module_args, zookeeper, server_role
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "name": server_role.name,
                "maintenance": True,
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == True
        assert e.value.role["type"] == server_role.type
        assert e.value.role["hostname"] == server_role.host_ref.hostname
        assert e.value.role["role_state"] == ApiRoleState.STARTED
        assert e.value.role["maintenance_mode"] == True

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == False
        assert e.value.role["maintenance_mode"] == True

    def test_service_role_existing_config(
        self, conn, module_args, zookeeper, updated_server_role_config
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "name": updated_server_role_config.name,
                "config": {
                    "minSessionTimeout": 5001,
                    "maxSessionTimeout": 50001,
                },
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == True
        assert e.value.role["type"] == updated_server_role_config.type
        assert e.value.role["hostname"] == updated_server_role_config.host_ref.hostname
        assert e.value.role["role_state"] == ApiRoleState.STARTED
        assert e.value.role["config"]["minSessionTimeout"] == "5001"
        assert e.value.role["config"]["maxSessionTimeout"] == "50001"

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == False
        assert e.value.role["config"]["minSessionTimeout"] == "5001"
        assert e.value.role["config"]["maxSessionTimeout"] == "50001"

    def test_service_role_existing_config_purge(
        self, conn, module_args, zookeeper, updated_server_role_config
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "name": updated_server_role_config.name,
                "config": {
                    "maxSessionTimeout": 50001,
                },
                "purge": True,
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == True
        assert e.value.role["type"] == updated_server_role_config.type
        assert e.value.role["hostname"] == updated_server_role_config.host_ref.hostname
        assert e.value.role["role_state"] == ApiRoleState.STARTED
        assert "minSessionTimeout" not in e.value.role["config"]
        assert e.value.role["config"]["maxSessionTimeout"] == "50001"

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == False
        assert "minSessionTimeout" not in e.value.role["config"]
        assert e.value.role["config"]["maxSessionTimeout"] == "50001"

    def test_service_role_existing_rcg(
        self, conn, module_args, zookeeper, server_role, custom_rcg_server_role
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "name": server_role.name,
                "role_config_group": custom_rcg_server_role.name,
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == True
        assert e.value.role["type"] == server_role.type
        assert e.value.role["hostname"] == server_role.host_ref.hostname
        assert e.value.role["role_state"] == ApiRoleState.STARTED
        assert e.value.role["config"]["minSessionTimeout"] == "4501"

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == False
        assert e.value.role["config"]["minSessionTimeout"] == "4501"

    def test_service_role_existing_rcg_base(
        self, conn, module_args, zookeeper, updated_server_role_rcg
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "name": updated_server_role_rcg.name,
                "role_config_group": None,
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == True
        assert e.value.role["type"] == updated_server_role_rcg.type
        assert e.value.role["hostname"] == updated_server_role_rcg.host_ref.hostname
        assert e.value.role["role_state"] == ApiRoleState.STARTED
        assert "minSessionTimeout" not in e.value.role["config"]

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == False
        assert "minSessionTimeout" not in e.value.role["config"]

    def test_service_role_existing_tags(
        self, conn, module_args, zookeeper, updated_server_role_tags
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "name": updated_server_role_tags.name,
                "tags": {
                    "pytest": "tag",
                },
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == True
        assert e.value.role["type"] == updated_server_role_tags.type
        assert e.value.role["hostname"] == updated_server_role_tags.host_ref.hostname
        assert e.value.role["role_state"] == ApiRoleState.STARTED
        assert e.value.role["tags"]["existing"] == "tag"
        assert e.value.role["tags"]["pytest"] == "tag"

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == False
        assert e.value.role["tags"]["existing"] == "tag"
        assert e.value.role["tags"]["pytest"] == "tag"

    def test_service_role_existing_tags_purge(
        self, conn, module_args, zookeeper, updated_server_role_tags
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "name": updated_server_role_tags.name,
                "tags": {
                    "pytest": "tag",
                },
                "purge": True,
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == True
        assert e.value.role["type"] == updated_server_role_tags.type
        assert e.value.role["hostname"] == updated_server_role_tags.host_ref.hostname
        assert e.value.role["role_state"] == ApiRoleState.STARTED
        assert "existing" not in e.value.role["tags"]
        assert e.value.role["tags"]["pytest"] == "tag"

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == False
        assert "existing" not in e.value.role["tags"]
        assert e.value.role["tags"]["pytest"] == "tag"

    def test_service_role_existing_state_started(
        self, conn, module_args, zookeeper, stopped_server_role
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "name": stopped_server_role.name,
                "state": "started",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == True
        assert e.value.role["type"] == stopped_server_role.type
        assert e.value.role["hostname"] == stopped_server_role.host_ref.hostname
        assert e.value.role["role_state"] == ApiRoleState.STARTED

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == False
        assert e.value.role["role_state"] == ApiRoleState.STARTED

    def test_service_role_existing_state_stopped(
        self, conn, module_args, zookeeper, server_role
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "name": server_role.name,
                "state": "stopped",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == True
        assert e.value.role["type"] == server_role.type
        assert e.value.role["hostname"] == server_role.host_ref.hostname
        assert e.value.role["role_state"] == ApiRoleState.STOPPED

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == False
        assert e.value.role["role_state"] == ApiRoleState.STOPPED

    def test_service_role_existing_state_restarted(
        self, conn, module_args, zookeeper, server_role
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "name": server_role.name,
                "state": "restarted",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == True
        assert e.value.role["type"] == server_role.type
        assert e.value.role["hostname"] == server_role.host_ref.hostname
        assert e.value.role["role_state"] == ApiRoleState.STARTED

        # Idempotency (rather, 'restarted' is not idempotent)
        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == True
        assert e.value.role["role_state"] == ApiRoleState.STARTED

    def test_service_role_existing_state_absent(
        self, conn, module_args, zookeeper, server_role
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "name": server_role.name,
                "state": "absent",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == True
        assert not e.value.role

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == False
        assert not e.value.role
