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
    ApiHostTemplate,
    ApiHostTemplateList,
    ApiHostRef,
    ApiRole,
    ApiRoleConfigGroup,
    ApiRoleConfigGroupRef,
    ApiService,
    HostTemplatesResourceApi,
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.modules import host_template_info

from ansible_collections.cloudera.cluster.plugins.module_utils.cluster_utils import (
    get_cluster_hosts,
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


def test_host_template_info_missing_cluster(conn, module_args):
    module_args(
        {
            **conn,
        },
    )

    with pytest.raises(AnsibleFailJson, match="missing required arguments: cluster"):
        host_template_info.main()


def test_host_template_info_named(
    conn,
    module_args,
    request,
    cm_api_client,
    base_cluster,
    zookeeper,
    host_template_factory,
):
    id = f"pytest-{request.node.name}"

    base_rcg = get_base_role_config_group(
        api_client=cm_api_client,
        cluster_name=zookeeper.cluster_ref.cluster_name,
        service_name=zookeeper.name,
        role_type="SERVER",
    )

    host_template_factory(
        cluster=base_cluster,
        host_template=ApiHostTemplate(
            name=id,
            role_config_group_refs=[
                ApiRoleConfigGroupRef(role_config_group_name=base_rcg.name),
            ],
        ),
    )

    module_args(
        {
            **conn,
            "cluster": base_cluster.name,
            "name": id,
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        host_template_info.main()

    assert len(e.value.host_templates) == 1


def test_host_template_info_not_found(conn, module_args, base_cluster):
    module_args(
        {
            **conn,
            "cluster": base_cluster.name,
            "name": "not_found",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        host_template_info.main()

    assert len(e.value.host_templates) == 0


def test_host_template_info_all(
    conn,
    module_args,
    request,
    cm_api_client,
    base_cluster,
    zookeeper,
    host_template_factory,
):
    id = f"pytest-{request.node.name}"

    base_rcg = get_base_role_config_group(
        api_client=cm_api_client,
        cluster_name=zookeeper.cluster_ref.cluster_name,
        service_name=zookeeper.name,
        role_type="SERVER",
    )

    host_template_factory(
        cluster=base_cluster,
        host_template=ApiHostTemplate(
            name=id,
            role_config_group_refs=[
                ApiRoleConfigGroupRef(role_config_group_name=base_rcg.name),
            ],
        ),
    )

    module_args(
        {
            **conn,
            "cluster": base_cluster.name,
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        host_template_info.main()

    assert len(e.value.host_templates) == 1
