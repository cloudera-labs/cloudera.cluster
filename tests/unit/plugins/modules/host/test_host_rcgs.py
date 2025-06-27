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

from ansible_collections.cloudera.cluster.plugins.module_utils.host_utils import (
    get_host_roles,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    create_role,
    provision_service_role,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    create_role_config_group,
    get_base_role_config_group,
)

from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


class TestHostRoleConfigGroups:
    def test_host_update_role_config_group_invalid_service(
        self,
        conn,
        module_args,
        available_hosts,
        zookeeper,
    ):

        target_host = available_hosts[0]

        # Set the role config
        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "role_config_groups": [
                    {
                        "service": "BOOM",
                        "type": "Example",
                    },
                ],
            },
        )

        with pytest.raises(AnsibleFailJson, match="Service 'BOOM' not found"):
            host.main()

    def test_host_update_role_config_group_invalid_type(
        self,
        conn,
        module_args,
        available_hosts,
        zookeeper,
    ):
        target_host = available_hosts[0]

        # Set the role config
        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "role_config_groups": [
                    {
                        "service": zookeeper.name,
                        "type": "BOOM",
                    },
                ],
            },
        )

        with pytest.raises(
            AnsibleFailJson,
            match="Base role config group for type, 'BOOM', not found",
        ):
            host.main()

    def test_host_update_role_config_group_invalid_name(
        self,
        conn,
        module_args,
        cm_api_client,
        available_hosts,
        zookeeper,
        role_config_group_factory,
        request,
    ):
        id = f"pytest-{Path(request.node.name).stem}"

        role_config_group_factory(
            service=zookeeper,
            role_config_group=create_role_config_group(
                api_client=cm_api_client,
                cluster_name=zookeeper.cluster_ref.cluster_name,
                service_name=zookeeper.name,
                name=id,
                role_type="SERVER",
            ),
        )

        target_host = available_hosts[0]

        # Set the role config
        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "role_config_groups": [
                    {
                        "service": zookeeper.name,
                        "name": "BOOM",
                    },
                ],
            },
        )

        with pytest.raises(
            AnsibleFailJson,
            match="The role config group 'BOOM' does not exist",
        ):
            host.main()

    def test_host_update_role_config_group_new_name(
        self,
        conn,
        module_args,
        cm_api_client,
        available_hosts,
        zookeeper,
        role_config_group_factory,
        request,
    ):
        id = f"pytest-{Path(request.node.name).stem}"

        target_rcg = role_config_group_factory(
            service=zookeeper,
            role_config_group=create_role_config_group(
                api_client=cm_api_client,
                cluster_name=zookeeper.cluster_ref.cluster_name,
                service_name=zookeeper.name,
                name=id,
                role_type="SERVER",
            ),
        )

        # Target a host without ZK Server
        target_host = available_hosts[0]

        # Set the role config
        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "role_config_groups": [
                    {
                        "service": zookeeper.name,
                        "name": target_rcg.name,
                    },
                ],
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True

        # Reread the host
        updated_host = HostsResourceApi(cm_api_client).read_host(
            host_id=target_host.host_id,
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
            host_id=target_host.host_id,
        )

        # Retrieve the current running roles on the host
        current_roles = get_host_roles(api_client=cm_api_client, host=updated_host)
        assert set(e.value.host["roles"]) == set([role.name for role in current_roles])
        assert target_rcg.name in [
            role.role_config_group_ref.role_config_group_name for role in current_roles
        ]

    def test_host_update_role_config_group_new_base(
        self,
        conn,
        module_args,
        cm_api_client,
        available_hosts,
        zookeeper,
    ):
        target_rcg = get_base_role_config_group(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_type="SERVER",
        )

        # Target a host without ZK Server
        target_host = available_hosts[0]

        # Set the role config
        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "role_config_groups": [
                    {
                        "service": zookeeper.name,
                        "name": target_rcg.name,
                    },
                ],
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True

        # Reread the host
        updated_host = HostsResourceApi(cm_api_client).read_host(
            host_id=target_host.host_id,
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
            host_id=target_host.host_id,
        )

        # Retrieve the current running roles on the host
        current_roles = get_host_roles(api_client=cm_api_client, host=updated_host)
        assert set(e.value.host["roles"]) == set([role.name for role in current_roles])
        assert target_rcg.name in [
            role.role_config_group_ref.role_config_group_name for role in current_roles
        ]

    def test_host_update_role_config_group_existing_name(
        self,
        conn,
        module_args,
        cm_api_client,
        available_hosts,
        base_cluster,
        zookeeper,
        role_config_group_factory,
        request,
    ):
        id = f"pytest-{Path(request.node.name).stem}"

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

        # Create a custom RCG for ZK SERVER
        target_rcg = role_config_group_factory(
            service=zookeeper,
            role_config_group=create_role_config_group(
                api_client=cm_api_client,
                cluster_name=zookeeper.cluster_ref.cluster_name,
                service_name=zookeeper.name,
                name=id,
                role_type="SERVER",
            ),
        )

        # Set the role config
        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "role_config_groups": [
                    {
                        "service": zookeeper.name,
                        "name": target_rcg.name,
                    },
                ],
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True

        # Reread the host
        updated_host = HostsResourceApi(cm_api_client).read_host(
            host_id=target_host.host_id,
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
            host_id=target_host.host_id,
        )

        # Retrieve the current running roles on the host
        current_roles = get_host_roles(api_client=cm_api_client, host=updated_host)
        assert set(e.value.host["roles"]) == set([role.name for role in current_roles])
        assert target_rcg.name in [
            role.role_config_group_ref.role_config_group_name for role in current_roles
        ]

    def test_host_update_role_config_group_existing_base(
        self,
        conn,
        module_args,
        cm_api_client,
        available_hosts,
        base_cluster,
        zookeeper,
    ):
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

        # Set the role config
        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "role_config_groups": [
                    {
                        "service": zookeeper.name,
                        "name": target_rcg.name,
                    },
                ],
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True

        # Reread the host
        updated_host = HostsResourceApi(cm_api_client).read_host(
            host_id=target_host.host_id,
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
            host_id=target_host.host_id,
        )

        # Retrieve the current running roles on the host
        current_roles = get_host_roles(api_client=cm_api_client, host=updated_host)
        assert set(e.value.host["roles"]) == set([role.name for role in current_roles])
        assert target_rcg.name in [
            role.role_config_group_ref.role_config_group_name for role in current_roles
        ]

    def test_host_update_role_config_group_purge_name(
        self,
        conn,
        module_args,
        cm_api_client,
        available_hosts,
        base_cluster,
        zookeeper,
        role_config_group_factory,
        request,
    ):
        id = f"pytest-{Path(request.node.name).stem}"

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

        # Create a custom RCG for ZK SERVER
        target_rcg = role_config_group_factory(
            service=zookeeper,
            role_config_group=create_role_config_group(
                api_client=cm_api_client,
                cluster_name=zookeeper.cluster_ref.cluster_name,
                service_name=zookeeper.name,
                name=id,
                role_type="SERVER",
            ),
        )

        # Set the role config
        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "role_config_groups": [
                    {
                        "service": zookeeper.name,
                        "name": target_rcg.name,
                    },
                ],
                "purge": True,
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True

        # Reread the host
        updated_host = HostsResourceApi(cm_api_client).read_host(
            host_id=target_host.host_id,
        )

        # Retrieve the current running roles on the host
        current_roles = get_host_roles(api_client=cm_api_client, host=updated_host)
        assert set(e.value.host["roles"]) == set([role.name for role in current_roles])
        assert set([target_rcg.name]) == set(
            [
                role.role_config_group_ref.role_config_group_name
                for role in current_roles
            ],
        )

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == False

        # Reread the host
        updated_host = HostsResourceApi(cm_api_client).read_host(
            host_id=target_host.host_id,
        )

        # Retrieve the current running roles on the host
        current_roles = get_host_roles(api_client=cm_api_client, host=updated_host)
        assert set(e.value.host["roles"]) == set([role.name for role in current_roles])
        assert set([target_rcg.name]) == set(
            [
                role.role_config_group_ref.role_config_group_name
                for role in current_roles
            ],
        )

    def test_host_update_role_config_group_purge_base(
        self,
        conn,
        module_args,
        cm_api_client,
        available_hosts,
        base_cluster,
        zookeeper,
    ):
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

        # Set the role config
        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "role_config_groups": [
                    {
                        "service": zookeeper.name,
                        "name": target_rcg.name,
                    },
                ],
                "purge": True,
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True

        # Reread the host
        updated_host = HostsResourceApi(cm_api_client).read_host(
            host_id=target_host.host_id,
        )

        # Retrieve the current running roles on the host
        current_roles = get_host_roles(api_client=cm_api_client, host=updated_host)
        assert set(e.value.host["roles"]) == set([role.name for role in current_roles])
        assert set([target_rcg.name]) == set(
            [
                role.role_config_group_ref.role_config_group_name
                for role in current_roles
            ],
        )

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == False

        # Reread the host
        updated_host = HostsResourceApi(cm_api_client).read_host(
            host_id=target_host.host_id,
        )

        # Retrieve the current running roles on the host
        current_roles = get_host_roles(api_client=cm_api_client, host=updated_host)
        assert set(e.value.host["roles"]) == set([role.name for role in current_roles])
        assert set([target_rcg.name]) == set(
            [
                role.role_config_group_ref.role_config_group_name
                for role in current_roles
            ],
        )
