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
    ApiConfigList,
    ApiHost,
    ApiHostList,
    ApiHostRef,
    ApiHostRefList,
    ApiHostTemplate,
    ApiHostTemplateList,
    ApiHostRef,
    ApiRole,
    ApiRoleConfigGroup,
    ApiRoleConfigGroupRef,
    ApiRoleList,
    ApiService,
    ClouderaManagerResourceApi,
    ClustersResourceApi,
    HostsResourceApi,
    HostTemplatesResourceApi,
    RolesResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.modules import host
from ansible_collections.cloudera.cluster.plugins.module_utils.cluster_utils import (
    get_cluster_hosts,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    read_roles,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.host_template_utils import (
    create_host_template_model,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    get_base_role_config_group,
)
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
    deregister_service,
    register_service,
)

LOG = logging.getLogger(__name__)


@pytest.fixture()
def available_hosts(cm_api_client) -> list[ApiHost]:
    return [
        h
        for h in HostsResourceApi(cm_api_client).read_hosts().items
        if h.cluster_ref is None
    ]


@pytest.fixture()
def cluster_hosts(cm_api_client, base_cluster) -> list[ApiHost]:
    return (
        ClustersResourceApi(cm_api_client)
        .list_hosts(cluster_name=base_cluster.name)
        .items
    )


@pytest.fixture(scope="module")
def zookeeper(cm_api_client, base_cluster, request) -> Generator[ApiService]:
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


@pytest.fixture(autouse=True)
def resettable_cluster(cm_api_client, base_cluster):
    host_api = HostsResourceApi(cm_api_client)
    cluster_api = ClustersResourceApi(cm_api_client)
    service_api = ServicesResourceApi(cm_api_client)
    role_api = RolesResourceApi(cm_api_client)

    # Keep track of attached hosts and their role assignments
    prior_hosts = dict[str, (ApiHost, dict[str, ApiRole])]()

    # Get all services on the cluster
    prior_services = service_api.read_services(
        cluster_name=base_cluster.name,
    ).items

    # For each host in the cluster, get a map of each service role type's instance
    for h in get_cluster_hosts(api_client=cm_api_client, cluster=base_cluster):
        prior_roles_by_service = dict[str, dict[str, ApiRole]]()

        # And for each service in the cluster
        for s in prior_services:
            # Retrieve any roles for the host
            prior_roles_by_service[s.name] = {
                r.type: r
                for r in read_roles(
                    api_client=cm_api_client,
                    cluster_name=base_cluster.name,
                    service_name=s.name,
                    host_id=h.host_id,
                ).items
            }

        # Add to the map of prior hosts
        prior_hosts[h.host_id] = (h, prior_roles_by_service)

    # yield to the tests
    yield base_cluster

    # Each current host
    for h in get_cluster_hosts(api_client=cm_api_client, cluster=base_cluster):
        # If new, remove
        if h.host_id not in prior_hosts:
            cluster_api.remove_host(
                cluster_name=base_cluster.name,
                host_id=h.host_id,
            )
        # Else, update host, host config, and roles
        else:
            (prior_host, prior_roles_by_service) = prior_hosts.pop(h.host_id)
            host_api.update_host(
                host_id=h.host_id,
                body=prior_host,
            )
            host_api.update_host_config(
                host_id=h.host_id,
                body=prior_host.config,
            )

            # Get current roles for the host by service
            for s in prior_services:
                current_roles = read_roles(
                    api_client=cm_api_client,
                    cluster_name=base_cluster.name,
                    service_name=s.name,
                    host_id=h.host_id,
                ).items

                # Retrieve the map of prior service roles (by type)
                prior_role_types = prior_roles_by_service.get(s.name)

                for current_role in current_roles:
                    # If the current has a new role type, remove it
                    if current_role.type not in prior_role_types:
                        role_api.delete_role(
                            cluster_name=base_cluster.name,
                            service_name=s.name,
                            role_name=current_role.name,
                        )
                    # Else, update the role and its config with the prior settings
                    else:
                        prior_role = prior_role_types.pop(current_role.type)

                        if not prior_role.config:
                            prior_role.config = ApiConfigList()

                        role_api.update_role_config(
                            cluster_name=base_cluster.name,
                            service_name=s.name,
                            role_name=current_role.name,
                            body=prior_role.config,
                        )

                # If a prior role type is missing, restore
                if prior_role_types:
                    for r in prior_role_types:
                        role_api.create_roles(
                            cluster_name=base_cluster.name,
                            service_name=r.service_ref.service_name,
                            body=ApiRoleList(items=[r]),
                        )

    # If missing, restore host and roles
    if prior_hosts:
        cluster_api.add_hosts(
            cluster_name=base_cluster.name,
            body=ApiHostRefList(
                items=[
                    ApiHostRef(host_id=prior_host.host_id, hostname=prior_host.hostname)
                    for prior_host in prior_hosts
                ]
            ),
        )


class TestHostArgSpec:
    def test_host_missing_required(self, conn, module_args):
        module_args(
            {
                **conn,
            }
        )

        with pytest.raises(
            AnsibleFailJson, match="one of the following is required: name, host_id"
        ) as e:
            host.main()

    def test_host_missing_attached_ip_address(self, conn, module_args):
        module_args(
            {
                **conn,
                "name": "example",
                "state": "attached",
            }
        )

        with pytest.raises(
            AnsibleFailJson,
            match="state is attached but all of the following are missing: cluster",
        ) as e:
            host.main()


# TODO Tackle the mutations first, as provisioning will require a host without CM agent...
@pytest.mark.skip()
class TestHostProvision:
    def test_host_create_missing_ip_address(self, conn, module_args):
        module_args(
            {
                **conn,
                "name": "pytest-host",
            }
        )

        with pytest.raises(
            AnsibleFailJson,
            match="Invalid host configuration. IP address is required for new hosts.",
        ) as e:
            host.main()

    def test_host_create_ip_address(self, conn, module_args, available_hosts):
        module_args(
            {
                **conn,
                "name": "pytest-host",
                "ip_address": available_hosts[0].ip_address,
            }
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()

    def test_host_create_rack_id(self, conn, module_args):
        module_args(
            {
                **conn,
            }
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()

    def test_host_create_host_template(self, conn, module_args):
        module_args(
            {
                **conn,
            }
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()

    def test_host_create_tags(self, conn, module_args):
        module_args(
            {
                **conn,
            }
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()

    def test_host_create_maintenance_enabled(self, conn, module_args):
        module_args(
            {
                **conn,
            }
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()


class TestHostModification:
    def test_host_update_ip_address(self, conn, module_args, cluster_hosts):
        target_host = cluster_hosts[0]

        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "ip_address": "10.0.0.1",
            }
        )

        with pytest.raises(AnsibleFailJson, match="To update the host IP address") as e:
            host.main()

    def test_host_update_rack_id(self, conn, module_args, cluster_hosts):
        target_host = cluster_hosts[0]

        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "rack_id": "/pytest1",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True
        assert e.value.host["rack_id"] == "/pytest1"

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == False
        assert e.value.host["rack_id"] == "/pytest1"

    def test_host_update_host_template(
        self,
        conn,
        module_args,
        request,
        cm_api_client,
        base_cluster,
        zookeeper,
        cluster_hosts,
        role_config_group_factory,
        host_template_factory,
    ):
        target_host = cluster_hosts[0]
        target_name = f"pytest-{Path(request.node.name)}"
        target_rcg = get_base_role_config_group(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_type="SERVER",
        )

        host_template = host_template_factory(
            cluster=base_cluster,
            host_template=create_host_template_model(
                cluster_name=base_cluster.name,
                name=target_name,
                role_config_groups=[target_rcg],
            ),
        )

        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "host_template": host_template.name,
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == False

    def test_host_update_host_template_new_role(self, conn, module_args):
        module_args(
            {
                **conn,
            }
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()

    def test_host_update_tags(self, conn, module_args):
        module_args(
            {
                **conn,
            }
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()

    def test_host_update_maintenance_enabled(self, conn, module_args):
        module_args(
            {
                **conn,
            }
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()

    def test_host_update_maintenance_disabled(self, conn, module_args):
        module_args(
            {
                **conn,
            }
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()


class TestHostAttached:
    def test_host_create_invalid_cluster(self, conn, module_args):
        module_args(
            {
                **conn,
            }
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()


class TestHostDetached:
    def test_host_create_invalid_cluster(self, conn, module_args):
        module_args(
            {
                **conn,
            }
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()


# def test_pytest_add_host_to_cloudera_manager(module_args):
#     module_args(
#         {
#             "username": os.getenv("CM_USERNAME"),
#             "password": os.getenv("CM_PASSWORD"),
#             "host": os.getenv("CM_HOST"),
#             "port": "7180",
#             "verify_tls": "no",
#             "debug": "no",
#             "cluster_hostname": "cloudera.host.example",
#             "rack_id": "/defo",
#             "cluster_host_ip": "10.10.1.1",
#             "state": "present",
#         }
#     )

#     with pytest.raises(AnsibleExitJson) as e:
#         host.main()

#     # LOG.info(str(e.value))
#     LOG.info(str(e.value.cloudera_manager))


# def test_pytest_attach_host_to_cluster(module_args):
#     module_args(
#         {
#             "username": os.getenv("CM_USERNAME"),
#             "password": os.getenv("CM_PASSWORD"),
#             "host": os.getenv("CM_HOST"),
#             "port": "7180",
#             "verify_tls": "no",
#             "debug": "no",
#             "cluster_hostname": "cloudera.host.example",
#             "name": "Cluster_Example",
#             "rack_id": "/defo",
#             "cluster_host_ip": "10.10.1.1",
#             "state": "attached",
#         }
#     )

#     with pytest.raises(AnsibleExitJson) as e:
#         host.main()

#     # LOG.info(str(e.value))
#     LOG.info(str(e.value.cloudera_manager))


# def test_pytest_detach_host_from_cluster(module_args):
#     module_args(
#         {
#             "username": os.getenv("CM_USERNAME"),
#             "password": os.getenv("CM_PASSWORD"),
#             "host": os.getenv("CM_HOST"),
#             "port": "7180",
#             "verify_tls": "no",
#             "debug": "no",
#             "cluster_hostname": "cloudera.host.example",
#             "name": "Cluster_Example",
#             "state": "detached",
#         }
#     )

#     with pytest.raises(AnsibleExitJson) as e:
#         host.main()

#     # LOG.info(str(e.value))
#     LOG.info(str(e.value.cloudera_manager))
