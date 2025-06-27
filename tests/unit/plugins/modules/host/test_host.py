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
    ApiEntityTag,
    ApiHost,
    HostsResourceApi,
)

from ansible_collections.cloudera.cluster.plugins.modules import host

from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


class TestHostArgSpec:
    def test_host_missing_required(self, conn, module_args):
        module_args(
            {
                **conn,
            },
        )

        with pytest.raises(
            AnsibleFailJson,
            match="one of the following is required: name, host_id",
        ) as e:
            host.main()

    def test_host_missing_host_template_cluster(self, conn, module_args):
        module_args(
            {
                **conn,
                "name": "example",
                "host_template": "example",
            },
        )

        with pytest.raises(
            AnsibleFailJson,
            match="required by 'host_template': cluster",
        ) as e:
            host.main()

    def test_host_missing_role_config_groups_cluster(self, conn, module_args):
        module_args(
            {
                **conn,
                "name": "example",
                "role_config_groups": [
                    {
                        "service": "example",
                        "type": "example",
                    },
                ],
            },
        )

        with pytest.raises(
            AnsibleFailJson,
            match="required by 'role_config_groups': cluster",
        ) as e:
            host.main()

    def test_host_missing_roles_cluster(self, conn, module_args):
        module_args(
            {
                **conn,
                "name": "example",
                "roles": [
                    {
                        "service": "example",
                        "type": "example",
                    },
                ],
            },
        )

        with pytest.raises(
            AnsibleFailJson,
            match="required by 'roles': cluster",
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
            },
        )

        with pytest.raises(
            AnsibleFailJson,
            match="Invalid host configuration. IP address is required for new hosts.",
        ) as e:
            host.main()

    def test_host_create_ip_address(self, conn, module_args, detached_hosts):
        module_args(
            {
                **conn,
                "name": "pytest-host",
                "ip_address": detached_hosts[0].ip_address,
            },
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()

    def test_host_create_rack_id(self, conn, module_args):
        module_args(
            {
                **conn,
            },
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()

    def test_host_create_host_template(self, conn, module_args):
        module_args(
            {
                **conn,
            },
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()

    def test_host_create_tags(self, conn, module_args):
        module_args(
            {
                **conn,
            },
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()

    def test_host_create_maintenance_enabled(self, conn, module_args):
        module_args(
            {
                **conn,
            },
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()


class TestHostModification:
    @pytest.fixture()
    def maintenance_enabled_host(
        self,
        cm_api_client,
        detached_hosts,
    ) -> Generator[ApiHost]:
        target_host = detached_hosts[0]

        # Set the host to maintenance mode if not already set
        if not target_host.maintenance_mode:
            HostsResourceApi(cm_api_client).enter_maintenance_mode(target_host.host_id)

        # Yield to the test
        yield target_host

        # Reset the maintenance mode
        if target_host.maintenance_mode:
            HostsResourceApi(cm_api_client).enter_maintenance_mode(target_host.host_id)
        else:
            HostsResourceApi(cm_api_client).exit_maintenance_mode(target_host.host_id)

    @pytest.fixture()
    def maintenance_disabled_host(
        self,
        cm_api_client,
        detached_hosts,
    ) -> Generator[ApiHost]:
        target_host = detached_hosts[0]

        # Unset the host to maintenance mode if not already set
        if target_host.maintenance_mode:
            HostsResourceApi(cm_api_client).exit_maintenance_mode(target_host.host_id)

        # Yield to the test
        yield target_host

        # Reset the maintenance mode
        if target_host.maintenance_mode:
            HostsResourceApi(cm_api_client).enter_maintenance_mode(target_host.host_id)
        else:
            HostsResourceApi(cm_api_client).exit_maintenance_mode(target_host.host_id)

    def test_host_update_ip_address(self, conn, module_args, attached_hosts):
        target_host = attached_hosts[0]

        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "ip_address": "10.0.0.1",
            },
        )

        with pytest.raises(AnsibleFailJson, match="To update the host IP address") as e:
            host.main()

    def test_host_update_rack_id(self, conn, module_args, attached_hosts):
        target_host = attached_hosts[0]

        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "rack_id": "/pytest1",
            },
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

    def test_host_update_tags(
        self,
        conn,
        module_args,
        cm_api_client,
        detached_hosts,
        resettable_host,
    ):
        HostsResourceApi(cm_api_client)

        # Get a detached host
        target_host = resettable_host(detached_hosts[0])

        # Update the host's tags
        HostsResourceApi(cm_api_client).add_tags(
            hostname=target_host.hostname,
            body=[
                ApiEntityTag(name="tag_one", value="Existing"),
                ApiEntityTag(name="tag_two", value="Existing"),
            ],
        )

        # Set the tags
        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "tags": {
                    "tag_one": "Updated",
                    "tag_three": "Added",
                },
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True
        assert e.value.host["tags"] == dict(
            tag_one="Updated",
            tag_two="Existing",
            tag_three="Added",
        )

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == False
        assert e.value.host["tags"] == dict(
            tag_one="Updated",
            tag_two="Existing",
            tag_three="Added",
        )

    def test_host_update_tags_purge(
        self,
        conn,
        module_args,
        cm_api_client,
        detached_hosts,
        resettable_host,
    ):
        HostsResourceApi(cm_api_client)

        # Get a detached host
        target_host = resettable_host(detached_hosts[0])

        # Update the host's tags
        HostsResourceApi(cm_api_client).add_tags(
            hostname=target_host.hostname,
            body=[
                ApiEntityTag(name="tag_one", value="Existing"),
                ApiEntityTag(name="tag_two", value="Existing"),
            ],
        )

        # Set the tags
        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "tags": {
                    "tag_one": "Updated",
                    "tag_three": "Added",
                },
                # Note that if using an attached host, be sure to include the cluster name
                # or purge will detach the host from the cluster!
                "purge": True,
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True
        assert e.value.host["tags"] == dict(tag_one="Updated", tag_three="Added")

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == False
        assert e.value.host["tags"] == dict(tag_one="Updated", tag_three="Added")

    def test_host_update_config(
        self,
        conn,
        module_args,
        cm_api_client,
        detached_hosts,
        resettable_host,
        request,
    ):
        id = Path(request.node.parent.name).stem
        HostsResourceApi(cm_api_client)

        # Get a detached host
        target_host = resettable_host(detached_hosts[0])

        # Update the host's tags
        HostsResourceApi(cm_api_client).update_host_config(
            host_id=target_host.host_id,
            message=f"pytest-{id}",
            body=ApiConfigList(
                items=[
                    ApiConfig(name="memory_overcommit_threshold", value="0.85"),
                    ApiConfig(name="host_memswap_window", value="16"),
                ],
            ),
        )

        # Set the tags
        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "config": {
                    "host_network_frame_errors_window": "20",
                    "host_memswap_window": "20",
                },
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True
        assert e.value.host["config"] == dict(
            memory_overcommit_threshold="0.85",
            host_memswap_window="20",
            host_network_frame_errors_window="20",
        )

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == False
        assert e.value.host["config"] == dict(
            memory_overcommit_threshold="0.85",
            host_memswap_window="20",
            host_network_frame_errors_window="20",
        )

    def test_host_update_config_purge(
        self,
        conn,
        module_args,
        cm_api_client,
        detached_hosts,
        resettable_host,
        request,
    ):
        id = Path(request.node.parent.name).stem
        HostsResourceApi(cm_api_client)

        # Get a detached host
        target_host = resettable_host(detached_hosts[0])

        # Update the host's tags
        HostsResourceApi(cm_api_client).update_host_config(
            host_id=target_host.host_id,
            message=f"pytest-{id}",
            body=ApiConfigList(
                items=[
                    ApiConfig(name="memory_overcommit_threshold", value="0.85"),
                    ApiConfig(name="host_memswap_window", value="16"),
                ],
            ),
        )

        # Set the tags
        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "config": {
                    "host_network_frame_errors_window": "20",
                    "host_memswap_window": "20",
                },
                "purge": True,
                # Note that if using an attached host, be sure to set 'cluster' or it will
                # be detached due to the 'purge' flag!
            },
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True
        assert e.value.host["config"] == dict(
            host_memswap_window="20",
            host_network_frame_errors_window="20",
        )

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == False
        assert e.value.host["config"] == dict(
            host_memswap_window="20",
            host_network_frame_errors_window="20",
        )

    def test_host_update_maintenance_enabled(
        self,
        conn,
        module_args,
        maintenance_disabled_host,
    ):
        module_args(
            {
                **conn,
                "name": maintenance_disabled_host.hostname,
                "maintenance": True,
            },
        )

        with pytest.raises(
            AnsibleExitJson,
        ) as e:
            host.main()

        assert e.value.changed == True
        assert e.value.host["maintenance_mode"] == True

        # Idempotency

        with pytest.raises(
            AnsibleExitJson,
        ) as e:
            host.main()

        assert e.value.changed == False
        assert e.value.host["maintenance_mode"] == True

    def test_host_update_maintenance_disabled(
        self,
        conn,
        module_args,
        maintenance_enabled_host,
    ):
        module_args(
            {
                **conn,
                "name": maintenance_enabled_host.hostname,
                "maintenance": False,
            },
        )

        with pytest.raises(
            AnsibleExitJson,
        ) as e:
            host.main()

        assert e.value.changed == True
        assert e.value.host["maintenance_mode"] == False

        # Idempotency

        with pytest.raises(
            AnsibleExitJson,
        ) as e:
            host.main()

        assert e.value.changed == False
        assert e.value.host["maintenance_mode"] == False
