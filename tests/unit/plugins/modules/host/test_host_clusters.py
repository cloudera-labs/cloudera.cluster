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
import random

from ansible_collections.cloudera.cluster.plugins.modules import host

from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


class TestHostAttachedCluster:
    def test_host_attach_invalid_cluster(
        self, conn, module_args, resettable_host, detached_hosts
    ):
        target_host = resettable_host(random.choice(detached_hosts))

        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "cluster": "BOOM",
            }
        )

        with pytest.raises(
            AnsibleFailJson,
            match="Cluster not found: BOOM",
        ):
            host.main()

    def test_host_attach_cluster(
        self, conn, module_args, base_cluster, resettable_host, detached_hosts
    ):
        target_host = resettable_host(random.choice(detached_hosts))

        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "cluster": base_cluster.name,
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True
        assert e.value.host["cluster_name"] == base_cluster.name

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == False
        assert e.value.host["cluster_name"] == base_cluster.name


@pytest.mark.skip("Requires set up of two clusters")
class TestHostMigrateClusters:
    def test_host_migrate_cluster(
        self, conn, module_args, base_cluster, resettable_host, detached_hosts
    ):
        target_host = resettable_host(random.choice(detached_hosts))

        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "cluster": base_cluster.name,
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True
        assert e.value.host["cluster_name"] == base_cluster.name

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == False
        assert e.value.host["cluster_name"] == base_cluster.name


class TestHostDetachedCluster:
    def test_host_detach(self, conn, module_args, attached_hosts, resettable_host):
        target_host = resettable_host(random.choice(attached_hosts))

        module_args(
            {
                **conn,
                "name": target_host.hostname,
                "purge": True,
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == True
        assert e.value.host["cluster_name"] == None

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            host.main()

        assert e.value.changed == False
        assert e.value.host["cluster_name"] == None


@pytest.mark.skip("Requires new host")
class TestHostCreate:
    pass


@pytest.mark.skip("Requires existing host")
class TestHostDestroy:
    pass
