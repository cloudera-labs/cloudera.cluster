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

from ansible_collections.cloudera.cluster.plugins.modules import host

from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    create_role,
    read_role,
)

from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


class TestHostRoleConfigs:
    def test_host_update_role_config_invalid_type(
        self,
        conn,
        module_args,
        cm_api_client,
        available_hosts,
        zookeeper,
        role_factory,
    ):
        role_model = create_role(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_type="SERVER",
            host_id=available_hosts[0].host_id,
        )

        existing_role = role_factory(
            service=zookeeper,
            role=role_model,
        )

        # Set the role config
        module_args(
            {
                **conn,
                "name": existing_role.host_ref.hostname,
                "cluster": existing_role.service_ref.cluster_name,
                "roles": [
                    {
                        "service": existing_role.service_ref.service_name,
                        "type": "BOOM",
                        "config": {
                            "maxSessionTimeout": 50001,
                            "process_start_secs": 31,
                        },
                    },
                ],
            },
        )

        with pytest.raises(AnsibleFailJson, match="No role of type, 'BOOM'"):
            host.main()

    def test_host_update_role_config(
        self,
        conn,
        module_args,
        cm_api_client,
        available_hosts,
        zookeeper,
        role_factory,
    ):
        role_model = create_role(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_type="SERVER",
            host_id=available_hosts[0].host_id,
            config={
                "minSessionTimeout": 5001,
                "maxSessionTimeout": 40000,
            },
        )

        existing_role = role_factory(
            service=zookeeper,
            role=role_model,
        )

        # Set the role config
        module_args(
            {
                **conn,
                "name": existing_role.host_ref.hostname,
                "cluster": existing_role.service_ref.cluster_name,
                "roles": [
                    {
                        "service": existing_role.service_ref.service_name,
                        "type": existing_role.type,
                        "config": {
                            "maxSessionTimeout": 50001,
                            "process_start_secs": 31,
                        },
                    },
                ],
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True

        updated_role = read_role(
            api_client=cm_api_client,
            cluster_name=existing_role.service_ref.cluster_name,
            service_name=existing_role.service_ref.service_name,
            role_name=existing_role.name,
        )

        assert (
            dict(
                minSessionTimeout="5001",
                maxSessionTimeout="50001",
                process_start_secs="31",
            ).items()
            <= {c.name: c.value for c in updated_role.config.items}.items()
        )

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == False

        updated_role = read_role(
            api_client=cm_api_client,
            cluster_name=existing_role.service_ref.cluster_name,
            service_name=existing_role.service_ref.service_name,
            role_name=existing_role.name,
        )

        assert (
            dict(
                minSessionTimeout="5001",
                maxSessionTimeout="50001",
                process_start_secs="31",
            ).items()
            <= {c.name: c.value for c in updated_role.config.items}.items()
        )

    def test_host_update_role_config_purge(
        self,
        conn,
        module_args,
        cm_api_client,
        available_hosts,
        zookeeper,
        role_factory,
    ):

        role_model = create_role(
            api_client=cm_api_client,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_type="SERVER",
            host_id=available_hosts[0].host_id,
            config={
                "minSessionTimeout": 5001,
                "maxSessionTimeout": 40000,
            },
        )

        existing_role = role_factory(
            service=zookeeper,
            role=role_model,
        )

        # Set the role config
        module_args(
            {
                **conn,
                "name": existing_role.host_ref.hostname,
                "cluster": existing_role.service_ref.cluster_name,
                "roles": [
                    {
                        "service": existing_role.service_ref.service_name,
                        "type": existing_role.type,
                        "config": {
                            "minSessionTimeout": 5001,
                            "process_start_secs": 31,
                        },
                    },
                ],
                "purge": True,
                "cluster": existing_role.service_ref.cluster_name,
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True

        updated_config = {
            c.name: c.value
            for c in read_role(
                api_client=cm_api_client,
                cluster_name=existing_role.service_ref.cluster_name,
                service_name=existing_role.service_ref.service_name,
                role_name=existing_role.name,
            ).config.items
        }

        assert (
            dict(
                minSessionTimeout="5001",
                process_start_secs="31",
            ).items()
            <= updated_config.items()
        )
        assert "maxSessionTimeout" not in updated_config

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == False

        updated_config = {
            c.name: c.value
            for c in read_role(
                api_client=cm_api_client,
                cluster_name=existing_role.service_ref.cluster_name,
                service_name=existing_role.service_ref.service_name,
                role_name=existing_role.name,
            ).config.items
        }

        assert (
            dict(
                minSessionTimeout="5001",
                process_start_secs="31",
            ).items()
            <= updated_config.items()
        )
        assert "maxSessionTimeout" not in updated_config
