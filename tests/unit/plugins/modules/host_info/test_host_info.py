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

from cm_client import (
    HostsResourceApi,
)

from ansible_collections.cloudera.cluster.plugins.modules import host_info

from ansible_collections.cloudera.cluster.plugins.module_utils.cluster_utils import (
    get_cluster_hosts,
)
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def test_host_info_host_id_invalid(conn, module_args):
    module_args(
        {
            **conn,
            "host_id": "BOOM",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        host_info.main()

    assert not e.value.hosts


def test_host_info_name_invalid(conn, module_args):
    module_args(
        {
            **conn,
            "name": "BOOM",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        host_info.main()

    assert not e.value.hosts


def test_host_info_cluster_invalid(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": "BOOM",
        },
    )

    with pytest.raises(AnsibleFailJson, match="Cluster does not exist: BOOM"):
        host_info.main()


def test_host_info_host_id(conn, module_args, cm_api_client):
    all_hosts = HostsResourceApi(cm_api_client).read_hosts().items

    module_args(
        {
            **conn,
            "host_id": all_hosts[0].host_id,
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        host_info.main()

    assert len(e.value.hosts) == 1
    assert e.value.hosts[0]["host_id"] == all_hosts[0].host_id


def test_host_info_name(conn, module_args, cm_api_client):
    all_hosts = HostsResourceApi(cm_api_client).read_hosts().items

    module_args(
        {
            **conn,
            "name": all_hosts[0].hostname,
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        host_info.main()

    assert len(e.value.hosts) == 1
    assert e.value.hosts[0]["host_id"] == all_hosts[0].host_id


def test_host_info_cluster(conn, module_args, cm_api_client, base_cluster):
    cluster_hosts = get_cluster_hosts(
        api_client=cm_api_client,
        cluster=base_cluster,
    )

    module_args(
        {
            **conn,
            "cluster": base_cluster.name,
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        host_info.main()

    assert len(e.value.hosts) == len(cluster_hosts)


def test_host_info_all(conn, module_args, cm_api_client):
    all_hosts = HostsResourceApi(cm_api_client).read_hosts().items

    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        host_info.main()

    assert len(e.value.hosts) == len(all_hosts)
