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

from ansible_collections.cloudera.cluster.plugins.modules import host_template

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


@pytest.fixture(autouse=True)
def resettable_host_templates(cm_api_client, base_cluster) -> Generator[None]:
    host_template_api = HostTemplatesResourceApi(cm_api_client)

    # Get the current state of host templates on the cluster
    initial_host_templates = {
        ht.name: ht
        for ht in host_template_api.read_host_templates(
            cluster_name=base_cluster.name,
        ).items
    }

    # Yield to tests
    yield

    # Reset host templates to initial set
    current_host_templates = host_template_api.read_host_templates(
        cluster_name=base_cluster.name,
    ).items

    # Each current host template
    for ht in current_host_templates:
        # If new, remove
        if ht.name not in initial_host_templates:
            host_template_api.delete_host_template(
                cluster_name=base_cluster.name,
                host_template_name=ht.name,
            )
        # Else, update/reset
        else:
            initial_ht = initial_host_templates.pop(ht.name)
            host_template_api.update_host_template(
                cluster_name=base_cluster.name,
                host_template_name=ht.name,
                body=initial_ht,
            )

    # If missing, restore
    if initial_host_templates:
        host_template_api.create_host_templates(
            cluster_name=base_cluster.name,
            body=ApiHostTemplateList(items=initial_host_templates.values()),
        )


@pytest.fixture()
def existing_host_template(
    cm_api_client, zookeeper, request
) -> Generator[ApiHostTemplate]:
    host_template_api = HostTemplatesResourceApi(cm_api_client)

    id = f"pytest-{request.node.name}"

    base_rcg = get_base_role_config_group(
        api_client=cm_api_client,
        cluster_name=zookeeper.cluster_ref.cluster_name,
        service_name=zookeeper.name,
        role_type="SERVER",
    )

    created_host_template = host_template_api.create_host_templates(
        cluster_name=zookeeper.cluster_ref.cluster_name,
        body=ApiHostTemplateList(
            items=[
                ApiHostTemplate(
                    name=id,
                    role_config_group_refs=[
                        ApiRoleConfigGroupRef(role_config_group_name=base_rcg.name),
                    ],
                )
            ]
        ),
    ).items[0]

    yield created_host_template

    try:
        host_template_api.delete_host_template(
            cluster_name=zookeeper.cluster_ref.cluster_name,
            host_template_name=created_host_template.name,
        )
    except ApiException as ex:
        if ex.status != 404:
            raise ex


def test_host_template_missing_cluster(conn, module_args):
    module_args(
        {
            **conn,
            "name": "EXAMPLE",
            "role_config_groups": [],
        }
    )

    with pytest.raises(
        AnsibleFailJson, match="missing required arguments: cluster"
    ) as e:
        host_template.main()


def test_host_template_missing_name(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": "EXAMPLE",
            "role_config_groups": [],
        }
    )

    with pytest.raises(AnsibleFailJson, match="missing required arguments: name") as e:
        host_template.main()


def test_host_template_missing_role_config_groups_on_present(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": "EXAMPLE",
            "name": "EXAMPLE",
        }
    )

    with pytest.raises(
        AnsibleFailJson,
        match="state is present but all of the following are missing: role_config_groups",
    ) as e:
        host_template.main()


def test_host_template_provision_invalid_cluster(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": "INVALID",
            "name": "Example",
            "role_config_groups": [
                {
                    "service": "zookeeper",
                    "type": "SERVER",
                }
            ],
        }
    )

    with pytest.raises(AnsibleFailJson, match="Cluster does not exist: INVALID") as e:
        host_template.main()


def test_host_template_provision_invalid_base_rcg_service(conn, module_args, zookeeper):
    module_args(
        {
            **conn,
            "cluster": zookeeper.cluster_ref.cluster_name,
            "name": "Example",
            "role_config_groups": [
                {
                    "service": "INVALID",
                    "type": "SERVER",
                }
            ],
        }
    )

    with pytest.raises(
        AnsibleFailJson, match="Service 'INVALID' not found in cluster"
    ) as e:
        host_template.main()


def test_host_template_provision_invalid_base_rcg_name(conn, module_args, zookeeper):
    module_args(
        {
            **conn,
            "cluster": zookeeper.cluster_ref.cluster_name,
            "name": "Example",
            "role_config_groups": [
                {
                    "service": zookeeper.name,
                    "type": "INVALID",
                }
            ],
        }
    )

    with pytest.raises(
        AnsibleFailJson,
        match=f"Role type 'INVALID' not found for service '{zookeeper.name}'",
    ) as e:
        host_template.main()


def test_host_template_provision_base_rcg(
    conn, module_args, cm_api_client, zookeeper, request
):
    id = f"pytest-{request.node.name}"

    base_rcg = get_base_role_config_group(
        api_client=cm_api_client,
        cluster_name=zookeeper.cluster_ref.cluster_name,
        service_name=zookeeper.name,
        role_type="SERVER",
    )

    module_args(
        {
            **conn,
            "cluster": zookeeper.cluster_ref.cluster_name,
            "name": id,
            "role_config_groups": [
                {
                    "service": zookeeper.name,
                    "type": base_rcg.role_type,
                }
            ],
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        host_template.main()

    assert e.value.changed == True
    assert e.value.host_template["name"] == id
    assert base_rcg.name in e.value.host_template["role_config_groups"]

    # Idempotency

    with pytest.raises(AnsibleExitJson) as e:
        host_template.main()

    assert e.value.changed == False
    assert e.value.host_template["name"] == id
    assert base_rcg.name in e.value.host_template["role_config_groups"]


def test_host_template_provision_custom_rcg(
    conn, module_args, zookeeper, role_config_group_factory, request
):
    id = f"pytest-{request.node.name}"

    custom_rcg = role_config_group_factory(
        service=zookeeper,
        role_config_group=ApiRoleConfigGroup(name=f"SERVER-{id}", role_type="SERVER"),
    )

    module_args(
        {
            **conn,
            "cluster": zookeeper.cluster_ref.cluster_name,
            "name": id,
            "role_config_groups": [
                {
                    "service": zookeeper.name,
                    "name": custom_rcg.name,
                }
            ],
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        host_template.main()

    assert e.value.changed == True
    assert e.value.host_template["name"] == id
    assert custom_rcg.name in e.value.host_template["role_config_groups"]

    # Idempotency

    with pytest.raises(AnsibleExitJson) as e:
        host_template.main()

    assert e.value.changed == False
    assert e.value.host_template["name"] == id
    assert custom_rcg.name in e.value.host_template["role_config_groups"]


def test_host_template_existing_duplicate_type(
    module_args,
    conn,
    zookeeper,
    role_config_group_factory,
    existing_host_template,
    request,
):
    id = f"pytest-{request.node.name}"

    custom_rcg = role_config_group_factory(
        service=zookeeper,
        role_config_group=ApiRoleConfigGroup(name=f"SERVER-{id}", role_type="SERVER"),
    )

    module_args(
        {
            **conn,
            "cluster": existing_host_template.cluster_ref.cluster_name,
            "name": existing_host_template.name,
            "role_config_groups": [
                {
                    "service": zookeeper.name,
                    "name": custom_rcg.name,
                }
            ],
        }
    )

    with pytest.raises(
        AnsibleFailJson,
        match="The template already contains a role config group for type SERVER",
    ):
        host_template.main()


def test_host_template_existing_add(
    module_args,
    conn,
    cm_api_client,
    zookeeper,
    role_config_group_factory,
    existing_host_template,
    request,
):
    host_template_api = HostTemplatesResourceApi(cm_api_client)

    id = f"pytest-{request.node.name}"

    custom_rcg = role_config_group_factory(
        service=zookeeper,
        role_config_group=ApiRoleConfigGroup(name=f"GATEWAY-{id}", role_type="GATEWAY"),
    )

    module_args(
        {
            **conn,
            "cluster": existing_host_template.cluster_ref.cluster_name,
            "name": existing_host_template.name,
            "role_config_groups": [
                {
                    "service": zookeeper.name,
                    "name": custom_rcg.name,
                }
            ],
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        host_template.main()

    assert e.value.changed == True
    assert e.value.host_template["name"] == existing_host_template.name
    assert custom_rcg.name in e.value.host_template["role_config_groups"]

    updated_host_template = host_template_api.read_host_template(
        cluster_name=existing_host_template.cluster_ref.cluster_name,
        host_template_name=existing_host_template.name,
    )
    assert set(
        [
            rcg_ref.role_config_group_name
            for rcg_ref in updated_host_template.role_config_group_refs
        ]
    ) == set(e.value.host_template["role_config_groups"])

    # Idempotency

    with pytest.raises(AnsibleExitJson) as e:
        host_template.main()

    assert e.value.changed == False
    assert e.value.host_template["name"] == existing_host_template.name
    assert custom_rcg.name in e.value.host_template["role_config_groups"]

    updated_host_template = host_template_api.read_host_template(
        cluster_name=existing_host_template.cluster_ref.cluster_name,
        host_template_name=existing_host_template.name,
    )
    assert set(
        [
            rcg_ref.role_config_group_name
            for rcg_ref in updated_host_template.role_config_group_refs
        ]
    ) == set(e.value.host_template["role_config_groups"])


def test_host_template_existing_purge(
    module_args,
    conn,
    cm_api_client,
    zookeeper,
    role_config_group_factory,
    existing_host_template,
    request,
):
    host_template_api = HostTemplatesResourceApi(cm_api_client)

    id = f"pytest-{request.node.name}"

    custom_rcg = role_config_group_factory(
        service=zookeeper,
        role_config_group=ApiRoleConfigGroup(name=f"SERVER-{id}", role_type="SERVER"),
    )

    module_args(
        {
            **conn,
            "cluster": existing_host_template.cluster_ref.cluster_name,
            "name": existing_host_template.name,
            "role_config_groups": [
                {
                    "service": zookeeper.name,
                    "name": custom_rcg.name,
                }
            ],
            "purge": True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        host_template.main()

    assert e.value.changed == True
    assert e.value.host_template["name"] == existing_host_template.name
    assert custom_rcg.name in e.value.host_template["role_config_groups"]

    updated_host_template = host_template_api.read_host_template(
        cluster_name=existing_host_template.cluster_ref.cluster_name,
        host_template_name=existing_host_template.name,
    )
    assert set(
        [
            rcg_ref.role_config_group_name
            for rcg_ref in updated_host_template.role_config_group_refs
        ]
    ) == set(e.value.host_template["role_config_groups"])

    # Idempotency

    with pytest.raises(AnsibleExitJson) as e:
        host_template.main()

    assert e.value.changed == False
    assert e.value.host_template["name"] == existing_host_template.name
    assert custom_rcg.name in e.value.host_template["role_config_groups"]

    updated_host_template = host_template_api.read_host_template(
        cluster_name=existing_host_template.cluster_ref.cluster_name,
        host_template_name=existing_host_template.name,
    )
    assert set(
        [
            rcg_ref.role_config_group_name
            for rcg_ref in updated_host_template.role_config_group_refs
        ]
    ) == set(e.value.host_template["role_config_groups"])


def test_host_template_state_absent(
    conn, module_args, cm_api_client, existing_host_template
):
    host_template_api = HostTemplatesResourceApi(cm_api_client)

    module_args(
        {
            **conn,
            "cluster": existing_host_template.cluster_ref.cluster_name,
            "name": existing_host_template.name,
            "state": "absent",
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        host_template.main()

    assert e.value.changed == True

    # Idempotency

    with pytest.raises(AnsibleExitJson) as e:
        host_template.main()

    assert e.value.changed == False
