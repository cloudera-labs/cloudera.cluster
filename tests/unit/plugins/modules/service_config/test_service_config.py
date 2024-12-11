# -*- coding: utf-8 -*-

# Copyright 2024 Cloudera, Inc. All Rights Reserved.
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
    ApiConfig,
    ApiService,
    ApiServiceConfig,
    ApiServiceList,
    ClustersResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.modules import service_config

from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
    wait_for_command,
)

LOG = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def target_service(cm_api_client, target_cluster, request):
    api = ServicesResourceApi(cm_api_client)
    cluster_api = ClustersResourceApi(cm_api_client)

    name = Path(request.node.name).stem + "_zookeeper"

    service = ApiService(
        name=name,
        type="ZOOKEEPER",
    )

    api.create_services(
        cluster_name=target_cluster.name, body=ApiServiceList(items=[service])
    )
    cluster_api.auto_assign_roles(cluster_name=target_cluster.name)

    # configure = cluster_api.auto_configure(cluster_name=target_cluster.name)
    wait_for_command(
        cm_api_client,
        api.first_run(cluster_name=target_cluster.name, service_name=name),
    )

    yield api.read_service(cluster_name=target_cluster.name, service_name=name)

    api.delete_service(cluster_name=target_cluster.name, service_name=name)


@pytest.fixture
def target_service_config(cm_api_client, target_service, request):
    marker = request.node.get_closest_marker("prepare")

    if marker is None:
        raise Exception("No prepare marker found.")
    elif "service_config" not in marker.kwargs:
        raise Exception("No 'service_config' parameter found.")

    service_api = ServicesResourceApi(cm_api_client)

    # Set the parameter(s)
    # Do so serially, since a failed update due to defaults (see ApiException) will cause remaining
    # configuration entries to not run. Long-term solution is to check-and-set, which is
    # what the Ansible modules do...
    for k, v in marker.kwargs["service_config"].items():
        try:
            service_api.update_service_config(
                cluster_name=target_service.cluster_ref.cluster_name,
                service_name=target_service.name,
                message=f"test_service_config::{request.node.name}:set",
                body=ApiServiceConfig(items=[ApiConfig(name=k, value=v)]),
            )
        except ApiException as ae:
            if ae.status != 400 or "delete with template" not in str(ae.body):
                raise Exception(str(ae))

    # Return the targeted service and go run the test
    yield target_service

    # Reset the parameter
    for k, v in marker.kwargs["service_config"].items():
        try:
            service_api.update_service_config(
                cluster_name=target_service.cluster_ref.cluster_name,
                service_name=target_service.name,
                message=f"test_service_config::{request.node.name}::reset",
                body=ApiServiceConfig(items=[ApiConfig(name=k, value=v)]),
            )
        except ApiException as ae:
            if ae.status != 400 or "delete with template" not in str(ae.body):
                raise Exception(str(ae))


def test_missing_required(conn, module_args):
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster, parameters, service"):
        service_config.main()


def test_missing_service(conn, module_args):
    module_args({**conn, "service": "example"})

    with pytest.raises(AnsibleFailJson, match="cluster, parameters"):
        service_config.main()


def test_missing_cluster(conn, module_args):
    module_args({**conn, "cluster": "example"})

    with pytest.raises(AnsibleFailJson, match="parameters, service"):
        service_config.main()


def test_missing_parameters(conn, module_args):
    module_args({**conn, "parameters": dict(test="example")})

    with pytest.raises(AnsibleFailJson, match="cluster, service"):
        service_config.main()


def test_present_invalid_cluster(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": "example",
            "service": "example",
            "parameters": dict(example="Example"),
        }
    )

    with pytest.raises(AnsibleFailJson, match="Cluster does not exist"):
        service_config.main()


def test_present_invalid_service(conn, module_args, target_service):
    module_args(
        {
            **conn,
            "cluster": target_service.cluster_ref.cluster_name,
            "service": "example",
            "parameters": dict(example="Example"),
        }
    )

    with pytest.raises(AnsibleFailJson, match="Service 'example' not found"):
        service_config.main()


def test_present_invalid_parameter(conn, module_args, target_service):
    module_args(
        {
            **conn,
            "cluster": target_service.cluster_ref.cluster_name,
            "service": target_service.name,
            "parameters": dict(example="Example"),
        }
    )

    with pytest.raises(
        AnsibleFailJson, match="Unknown configuration attribute 'example'"
    ):
        service_config.main()


@pytest.mark.prepare(service_config=dict(autopurgeSnapRetainCount=None, tickTime=1111))
def test_set_parameters(conn, module_args, target_service_config):
    module_args(
        {
            **conn,
            "cluster": target_service_config.cluster_ref.cluster_name,
            "service": target_service_config.name,
            "parameters": dict(autopurgeSnapRetainCount=9),
            "message": "test_service_config::test_set_parameters",
            # "_ansible_check_mode": True,
            # "_ansible_diff": True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_config.main()

    assert e.value.changed == True
    assert {c["name"]: c["value"] for c in e.value.config}[
        "autopurgeSnapRetainCount"
    ] == "9"
    assert len(e.value.config) == 2

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        service_config.main()

    assert e.value.changed == False
    assert {c["name"]: c["value"] for c in e.value.config}[
        "autopurgeSnapRetainCount"
    ] == "9"
    assert len(e.value.config) == 2


@pytest.mark.prepare(service_config=dict(autopurgeSnapRetainCount=7, tickTime=1111))
def test_unset_parameters(conn, module_args, target_service_config):
    module_args(
        {
            **conn,
            "cluster": target_service_config.cluster_ref.cluster_name,
            "service": target_service_config.name,
            "parameters": dict(autopurgeSnapRetainCount=None),
            "message": "test_service_config::test_unset_parameters",
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_config.main()

    assert e.value.changed == True
    results = {c["name"]: c["value"] for c in e.value.config}
    assert "autopurgeSnapRetainCount" not in results
    assert len(e.value.config) == 1

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        service_config.main()

    assert e.value.changed == False
    results = {c["name"]: c["value"] for c in e.value.config}
    assert "autopurgeSnapRetainCount" not in results
    assert len(e.value.config) == 1


@pytest.mark.prepare(service_config=dict(autopurgeSnapRetainCount=7, tickTime=1111))
def test_set_parameters_with_purge(conn, module_args, target_service_config):
    module_args(
        {
            **conn,
            "cluster": target_service_config.cluster_ref.cluster_name,
            "service": target_service_config.name,
            "parameters": dict(autopurgeSnapRetainCount=9),
            "purge": True,
            "message": "test_service_config::test_set_parameters_with_purge",
            # "_ansible_check_mode": True,
            # "_ansible_diff": True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_config.main()

    assert e.value.changed == True
    assert {c["name"]: c["value"] for c in e.value.config}[
        "autopurgeSnapRetainCount"
    ] == "9"
    assert len(e.value.config) == 1

    with pytest.raises(AnsibleExitJson) as e:
        service_config.main()

    assert e.value.changed == False
    assert {c["name"]: c["value"] for c in e.value.config}[
        "autopurgeSnapRetainCount"
    ] == "9"
    assert len(e.value.config) == 1


@pytest.mark.prepare(service_config=dict(autopurgeSnapRetainCount=8, tickTime=2222))
def test_purge_all_parameters(conn, module_args, target_service_config):
    module_args(
        {
            **conn,
            "cluster": target_service_config.cluster_ref.cluster_name,
            "service": target_service_config.name,
            "parameters": dict(),
            "purge": True,
            "message": "test_service_config::test_purge_all_parameters",
            # "_ansible_check_mode": True,
            # "_ansible_diff": True,
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_config.main()

    assert e.value.changed == True
    assert len(e.value.config) == 0

    with pytest.raises(AnsibleExitJson) as e:
        service_config.main()

    assert e.value.changed == False
    assert len(e.value.config) == 0
