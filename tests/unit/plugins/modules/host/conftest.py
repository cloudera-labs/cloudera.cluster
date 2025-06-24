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

from collections.abc import Callable, Generator
from pathlib import Path

from cm_client import (
    ApiConfigList,
    ApiHost,
    ApiHostRef,
    ApiHostRefList,
    ApiHostRef,
    ApiHostsToRemoveArgs,
    ApiRole,
    ApiRoleList,
    ApiService,
    ClustersResourceApi,
    HostsResourceApi,
    RolesResourceApi,
    ServicesResourceApi,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    reconcile_config_list_updates,
    wait_command,
    wait_commands,
    TagUpdates,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.cluster_utils import (
    get_cluster_hosts,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    read_roles,
)
from ansible_collections.cloudera.cluster.tests.unit import (
    deregister_service,
    register_service,
)

LOG = logging.getLogger(__name__)


@pytest.fixture()
def detached_hosts(cm_api_client) -> list[ApiHost]:
    return [
        h
        for h in HostsResourceApi(cm_api_client).read_hosts().items
        if h.cluster_ref is None
    ]


@pytest.fixture()
def attached_hosts(cm_api_client, base_cluster) -> list[ApiHost]:
    return (
        ClustersResourceApi(cm_api_client)
        .list_hosts(cluster_name=base_cluster.name)
        .items
    )


@pytest.fixture()
def available_hosts(cm_api_client, attached_hosts) -> list[ApiHost]:
    return [
        host
        for host in attached_hosts
        if not HostsResourceApi(cm_api_client).read_host(host_id=host.host_id).role_refs
    ]


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


# TODO Split into a new module and scope to its functions
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
                        # Wait for any active commands
                        active_cmds = role_api.list_active_commands(
                            cluster_name=base_cluster.name,
                            service_name=s.name,
                            role_name=current_role.name,
                        )
                        wait_commands(
                            api_client=cm_api_client,
                            commands=active_cmds,
                        )
                        # Delete the role
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
                ],
            ),
        )


@pytest.fixture()
def resettable_host(cm_api_client, request) -> Generator[Callable[[ApiHost], ApiHost]]:
    host_api = HostsResourceApi(cm_api_client)
    cluster_api = ClustersResourceApi(cm_api_client)

    # Registry of resettable hosts
    registry = list[ApiHost]()

    # Yield the host wrapper to the tests
    def _wrapper(host: ApiHost) -> ApiHost:
        registry.append(host)
        return host

    yield _wrapper

    # Get current set of hosts
    current_hosts_map = dict[str, ApiHost]()
    for host in host_api.read_hosts(view="full").items:
        host.config = host_api.read_host_config(host.host_id)
        current_hosts_map[host.host_id] = host

    # Reset each host
    for previous_host in registry:
        target_host = current_hosts_map.get(previous_host.host_id, None)

        # If the host was deleted, recreate
        if target_host is None:
            # TODO Handle host creation
            pass
        else:
            # Tags
            tag_updates = TagUpdates(
                target_host.tags,
                {t.name: t.value for t in previous_host.tags},
                True,
            )
            if tag_updates.deletions:
                host_api.delete_tags(
                    hostname=target_host.hostname,
                    body=tag_updates.deletions,
                )

            if tag_updates.additions:
                host_api.add_tags(
                    hostname=target_host.hostname,
                    body=tag_updates.additions,
                )

            # Config
            if previous_host.config is None:
                previous_host.config = ApiConfigList(items=[])

            (updated_config, _, _) = reconcile_config_list_updates(
                target_host.config,
                {c.name: c.value for c in previous_host.config.items},
                True,
                False,
            )

            host_api.update_host_config(
                host_id=target_host.host_id,
                message=f"{Path(request.node.parent.name).stem}::{request.node.name}",
                body=updated_config,
            )

            # Cluster
            if (
                previous_host.cluster_ref is not None
                and target_host.cluster_ref is not None
                and previous_host.cluster_ref.cluster_name
                != target_host.cluster_ref.cluster_name
            ) or (
                previous_host.cluster_ref is None
                and target_host.cluster_ref is not None
            ):
                decommission_cmd = host_api.remove_hosts_from_cluster(
                    body=ApiHostsToRemoveArgs(hosts_to_remove=[target_host.hostname]),
                )
                wait_command(
                    api_client=cm_api_client,
                    command=decommission_cmd,
                )

            if (
                previous_host.cluster_ref is not None
                and target_host.cluster_ref is not None
                and previous_host.cluster_ref.cluster_name
                != target_host.cluster_ref.cluster_name
            ) or (
                previous_host.cluster_ref is not None
                and target_host.cluster_ref is None
            ):
                cluster_api.add_hosts(
                    cluster_name=previous_host.cluster_ref.cluster_name,
                    body=ApiHostRefList(
                        items=[
                            ApiHostRef(
                                host_id=target_host.host_id,
                                hostname=previous_host.hostname,
                            ),
                        ],
                    ),
                )

            # Roles
