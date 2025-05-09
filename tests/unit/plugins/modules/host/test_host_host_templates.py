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
    HostsResourceApi,
)

from ansible_collections.cloudera.cluster.plugins.modules import host

from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    create_role,
    provision_service_role,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.host_template_utils import (
    create_host_template_model,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.host_utils import (
    get_host_roles,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    get_base_role_config_group,
)
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
)

LOG = logging.getLogger(__name__)


class TestHostHostTemplates:
    def test_host_update_host_template_new(
        self,
        conn,
        module_args,
        request,
        cm_api_client,
        base_cluster,
        zookeeper,
        available_hosts,
        host_template_factory,
    ):
        target_name = f"pytest-{Path(request.node.name)}"

        # Get an existing, non-ZK SERVER host
        target_host = available_hosts[0]

        # Get the base RCG for ZK SERVER
        target_rcg = get_base_role_config_group(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_type="SERVER",
        )

        # Create a host template and assign the base ZK SERVER RCG
        host_template = host_template_factory(
            cluster=base_cluster,
            host_template=create_host_template_model(
                cluster_name=base_cluster.name,
                name=target_name,
                role_config_groups=[target_rcg],
            ),
        )

        # Set the host template
        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "cluster": target_host.cluster_ref.cluster_name,
                "host_template": host_template.name,
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True

        # Reread the host
        updated_host = HostsResourceApi(cm_api_client).read_host(
            host_id=target_host.host_id
        )

        # Retrieve the current running roles on the host
        current_roles = get_host_roles(api_client=cm_api_client, host=updated_host)
        assert set(e.value.host["roles"]) == set([role.name for role in current_roles])
        assert target_rcg.name in [
            role.role_config_group_ref.role_config_group_name for role in current_roles
        ]

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == False

        # Reread the host
        updated_host = HostsResourceApi(cm_api_client).read_host(
            host_id=target_host.host_id
        )

        # Retrieve the current running roles on the host
        current_roles = get_host_roles(api_client=cm_api_client, host=updated_host)
        assert set(e.value.host["roles"]) == set([role.name for role in current_roles])
        assert target_rcg.name in [
            role.role_config_group_ref.role_config_group_name for role in current_roles
        ]

    def test_host_update_host_template_existing(
        self,
        conn,
        module_args,
        request,
        cm_api_client,
        base_cluster,
        zookeeper,
        available_hosts,
        host_template_factory,
    ):
        target_name = f"pytest-{Path(request.node.name)}"

        # Get an existing, non-ZK SERVER host
        target_host = available_hosts[0]

        # Add an existing role to the target host
        existing_role = create_role(
            api_client=cm_api_client,
            cluster_name=base_cluster.name,
            service_name=zookeeper.name,
            role_type="GATEWAY",
            host_id=target_host.host_id,
        )

        # Provision the existing role to the target host
        existing_role = provision_service_role(
            api_client=cm_api_client,
            cluster_name=base_cluster.name,
            service_name=zookeeper.name,
            role=existing_role,
        )

        # Get the base RCG for ZK SERVER
        target_rcg = get_base_role_config_group(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_type="SERVER",
        )

        # Create a host template and assign the base ZK SERVER RCG
        host_template = host_template_factory(
            cluster=base_cluster,
            host_template=create_host_template_model(
                cluster_name=base_cluster.name,
                name=target_name,
                role_config_groups=[target_rcg],
            ),
        )

        # Set the host template
        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "cluster": target_host.cluster_ref.cluster_name,
                "host_template": host_template.name,
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True

        # Reread the host
        updated_host = HostsResourceApi(cm_api_client).read_host(
            host_id=target_host.host_id
        )

        # Retrieve the current running roles on the host
        current_roles = get_host_roles(api_client=cm_api_client, host=updated_host)
        assert set(e.value.host["roles"]) == set([role.name for role in current_roles])
        assert set(
            [
                target_rcg.name,
                existing_role.role_config_group_ref.role_config_group_name,
            ]
        ) == set(
            [
                role.role_config_group_ref.role_config_group_name
                for role in current_roles
            ]
        )

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == False

        # Reread the host
        updated_host = HostsResourceApi(cm_api_client).read_host(
            host_id=target_host.host_id
        )

        # Retrieve the current running roles on the host
        current_roles = get_host_roles(api_client=cm_api_client, host=updated_host)
        assert set(e.value.host["roles"]) == set([role.name for role in current_roles])
        assert set(
            [
                target_rcg.name,
                existing_role.role_config_group_ref.role_config_group_name,
            ]
        ) == set(
            [
                role.role_config_group_ref.role_config_group_name
                for role in current_roles
            ]
        )

    def test_host_update_host_template_purge(
        self,
        conn,
        module_args,
        request,
        cm_api_client,
        base_cluster,
        zookeeper,
        available_hosts,
        host_template_factory,
    ):
        target_name = f"pytest-{Path(request.node.name)}"

        # Get an existing, non-ZK SERVER host
        target_host = available_hosts[0]

        # Add an existing role to the target host
        existing_role = create_role(
            api_client=cm_api_client,
            cluster_name=base_cluster.name,
            service_name=zookeeper.name,
            role_type="GATEWAY",
            host_id=target_host.host_id,
        )

        # Provision the existing role to the target host
        existing_role = provision_service_role(
            api_client=cm_api_client,
            cluster_name=base_cluster.name,
            service_name=zookeeper.name,
            role=existing_role,
        )

        # Get the base RCG for ZK SERVER
        target_rcg = get_base_role_config_group(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_type="SERVER",
        )

        # Create a host template and assign the base ZK SERVER RCG
        host_template = host_template_factory(
            cluster=base_cluster,
            host_template=create_host_template_model(
                cluster_name=base_cluster.name,
                name=target_name,
                role_config_groups=[target_rcg],
            ),
        )

        # Set the host template
        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "cluster": target_host.cluster_ref.cluster_name,
                "host_template": host_template.name,
                "purge": True,
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True

        # Reread the host
        updated_host = HostsResourceApi(cm_api_client).read_host(
            host_id=target_host.host_id
        )

        # Retrieve the current running roles on the host
        current_roles = get_host_roles(api_client=cm_api_client, host=updated_host)
        assert set(e.value.host["roles"]) == set([role.name for role in current_roles])
        assert set([target_rcg.name]) == set(
            [
                role.role_config_group_ref.role_config_group_name
                for role in current_roles
            ]
        )

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == False

        # Reread the host
        updated_host = HostsResourceApi(cm_api_client).read_host(
            host_id=target_host.host_id
        )

        # Retrieve the current running roles on the host
        current_roles = get_host_roles(api_client=cm_api_client, host=updated_host)
        assert set(e.value.host["roles"]) == set([role.name for role in current_roles])
        assert set([target_rcg.name]) == set(
            [
                role.role_config_group_ref.role_config_group_name
                for role in current_roles
            ]
        )
