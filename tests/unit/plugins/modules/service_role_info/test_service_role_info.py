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
import os
import pytest

from cm_client import (
    ApiClient,
    ApiRole,
    RolesResourceApi,
)

from ansible_collections.cloudera.cluster.plugins.modules import service_role_info
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def read_expected_roles(
    api_client: ApiClient, cluster_name: str, service_name: str
) -> list[ApiRole]:
    return (
        RolesResourceApi(api_client)
        .read_roles(
            cluster_name=cluster_name,
            service_name=service_name,
        )
        .items
    )


def test_service_role_info_missing_required(conn, module_args):
    module_args({**conn})

    with pytest.raises(AnsibleFailJson, match="cluster"):
        service_role_info.main()


def test_service_role_info_missing_cluster(conn, module_args):
    module_args(
        {
            **conn,
            "service": "example",
        }
    )

    with pytest.raises(AnsibleFailJson, match="cluster"):
        service_role_info.main()


def test_service_role_info_invalid_service(conn, module_args, zk_session):
    module_args(
        {
            **conn,
            "cluster": zk_session.cluster_ref.cluster_name,
            "service": "BOOM",
        }
    )

    with pytest.raises(AnsibleFailJson, match="Service 'BOOM' not found in cluster"):
        service_role_info.main()


def test_service_role_info_invalid_cluster(conn, module_args, zk_session):
    module_args(
        {
            **conn,
            "cluster": "BOOM",
            "service": zk_session.name,
        }
    )

    with pytest.raises(AnsibleFailJson, match="Cluster does not exist: BOOM"):
        service_role_info.main()


def test_service_role_info_all(conn, module_args, cm_api_client, zk_session):
    roles = read_expected_roles(
        api_client=cm_api_client,
        cluster_name=zk_session.cluster_ref.cluster_name,
        service_name=zk_session.name,
    )

    module_args(
        {
            **conn,
            "cluster": zk_session.cluster_ref.cluster_name,
            "service": zk_session.name,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_info.main()

    assert len(e.value.roles) == len(roles)


def test_service_role_info_all_ful(conn, module_args, cm_api_client, zk_session):
    roles = read_expected_roles(
        api_client=cm_api_client,
        cluster_name=zk_session.cluster_ref.cluster_name,
        service_name=zk_session.name,
    )

    module_args(
        {
            **conn,
            "cluster": zk_session.cluster_ref.cluster_name,
            "service": zk_session.name,
            "view": "full",
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_info.main()

    assert len(e.value.roles) == len(roles)


def test_service_role_info_by_name(conn, module_args, cm_api_client, zk_session):
    roles = read_expected_roles(
        api_client=cm_api_client,
        cluster_name=zk_session.cluster_ref.cluster_name,
        service_name=zk_session.name,
    )

    module_args(
        {
            **conn,
            "cluster": zk_session.cluster_ref.cluster_name,
            "service": zk_session.name,
            "role": roles[0].name,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_info.main()

    assert len(e.value.roles) == 1
    assert e.value.roles[0]["name"] == roles[0].name


def test_service_role_info_by_type(conn, module_args, cm_api_client, zk_session):
    role_type = "SERVER"

    roles = [
        r
        for r in read_expected_roles(
            api_client=cm_api_client,
            cluster_name=zk_session.cluster_ref.cluster_name,
            service_name=zk_session.name,
        )
        if r.type == role_type
    ]

    module_args(
        {
            **conn,
            "cluster": zk_session.cluster_ref.cluster_name,
            "service": zk_session.name,
            "type": role_type,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_info.main()

    assert len(e.value.roles) == len(roles)


def test_service_role_info_by_hostname(conn, module_args, cm_api_client, zk_session):
    roles = read_expected_roles(
        api_client=cm_api_client,
        cluster_name=zk_session.cluster_ref.cluster_name,
        service_name=zk_session.name,
    )

    module_args(
        {
            **conn,
            "cluster": zk_session.cluster_ref.cluster_name,
            "service": zk_session.name,
            "cluster_hostname": roles[0].host_ref.hostname,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_info.main()

    assert len(e.value.roles) == 1
    assert e.value.roles[0]["host_id"] == roles[0].host_ref.host_id
    assert e.value.roles[0]["hostname"] == roles[0].host_ref.hostname


def test_service_role_info_by_host_id(conn, module_args, cm_api_client, zk_session):
    roles = read_expected_roles(
        api_client=cm_api_client,
        cluster_name=zk_session.cluster_ref.cluster_name,
        service_name=zk_session.name,
    )

    module_args(
        {
            **conn,
            "cluster": zk_session.cluster_ref.cluster_name,
            "service": zk_session.name,
            "cluster_host_id": roles[0].host_ref.host_id,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_info.main()

    assert len(e.value.roles) == 1
    assert e.value.roles[0]["host_id"] == roles[0].host_ref.host_id
    assert e.value.roles[0]["hostname"] == roles[0].host_ref.hostname
