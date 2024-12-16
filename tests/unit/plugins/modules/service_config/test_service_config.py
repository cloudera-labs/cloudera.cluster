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
import os
import pytest
import random
import string

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
    provision_service,
    service_wide_config,
)

LOG = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def zk_service(cm_api_client, base_cluster, request):
    if os.getenv("CM_SERVICE_ZOOKEEPER", None):
        api = ServicesResourceApi(cm_api_client)
        yield api.read_service(
            cluster_name=base_cluster.name,
            service_name=os.getenv("CM_SERVICE_ZOOKEEPER"),
        )
    else:
        name = (
            Path(request.fixturename).stem
            + "_"
            + "".join(random.choices(string.ascii_lowercase, k=6))
        )
        yield from provision_service(
            api_client=cm_api_client,
            cluster=base_cluster,
            service_name=name,
            service_type="ZOOKEEPER",
        )


@pytest.fixture(scope="function")
def zk_service_config(cm_api_client, zk_service, request):
    marker = request.node.get_closest_marker("service_config")

    if marker is None:
        raise Exception("No service_config marker found.")

    yield from service_wide_config(
        api_client=cm_api_client,
        service=zk_service,
        params=marker.args[0],
        message=f"test_service_config::{request.node.name}",
    )


@pytest.fixture(scope="module")
def target_service(cm_api_client, base_cluster, request):
    api = ServicesResourceApi(cm_api_client)

    if os.getenv("CM_SERVICE_NAME", None):
        yield api.read_service(
            cluster_name=base_cluster.name, service_name=os.getenv("CM_SERVICE_NAME")
        )
    else:
        cluster_api = ClustersResourceApi(cm_api_client)
        name = Path(request.node.name).stem + "_zookeeper"

        service = ApiService(
            name=name,
            type="ZOOKEEPER",
        )

        api.create_services(
            cluster_name=base_cluster.name, body=ApiServiceList(items=[service])
        )
        cluster_api.auto_assign_roles(cluster_name=base_cluster.name)

        # configure = cluster_api.auto_configure(cluster_name=target_cluster.name)
        wait_for_command(
            cm_api_client,
            api.first_run(cluster_name=base_cluster.name, service_name=name),
        )

        yield api.read_service(cluster_name=base_cluster.name, service_name=name)

        api.delete_service(cluster_name=base_cluster.name, service_name=name)


@pytest.fixture
def target_service_config(cm_api_client, target_service, request):
    marker = request.node.get_closest_marker("prepare")

    if marker is None:
        raise Exception("No prepare marker found.")
    elif "service_config" not in marker.kwargs:
        raise Exception("No 'service_config' parameter found.")

    service_api = ServicesResourceApi(cm_api_client)

    # Retrieve all of the pre-setup configurations
    pre = service_api.read_service_config(
        cluster_name=target_service.cluster_ref.cluster_name,
        service_name=target_service.name,
    )

    # Set the test configurations
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

    # Retrieve all of the post-setup configurations
    post = service_api.read_service_config(
        cluster_name=target_service.cluster_ref.cluster_name,
        service_name=target_service.name,
    )

    # Reconcile the configurations
    pre_set = set([c.name for c in pre.items])

    reconciled = pre.items.copy()
    reconciled.extend(
        [
            ApiConfig(name=k.name, value=None)
            for k in post.items
            if k.name not in pre_set
        ]
    )

    service_api.update_service_config(
        cluster_name=target_service.cluster_ref.cluster_name,
        service_name=target_service.name,
        message=f"test_service_config::{request.node.name}::reset",
        body=ApiServiceConfig(items=reconciled),
    )


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


@pytest.mark.service_config(dict(autopurgeSnapRetainCount=None, tickTime=1111))
def test_set_parameters(conn, module_args, zk_service_config):
    module_args(
        {
            **conn,
            "cluster": zk_service_config.cluster_ref.cluster_name,
            "service": zk_service_config.name,
            "parameters": dict(autopurgeSnapRetainCount=9),
            "message": "test_service_config::test_set_parameters",
            # "_ansible_check_mode": True,
            # "_ansible_diff": True,
        }
    )

    expected = dict(autopurgeSnapRetainCount="9", tickTime="1111")

    with pytest.raises(AnsibleExitJson) as e:
        service_config.main()

    assert e.value.changed == True
    assert expected.items() <= {c["name"]: c["value"] for c in e.value.config}.items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        service_config.main()

    assert e.value.changed == False
    assert expected.items() <= {c["name"]: c["value"] for c in e.value.config}.items()


@pytest.mark.service_config(dict(autopurgeSnapRetainCount=7, tickTime=1111))
def test_unset_parameters(conn, module_args, zk_service_config):
    module_args(
        {
            **conn,
            "cluster": zk_service_config.cluster_ref.cluster_name,
            "service": zk_service_config.name,
            "parameters": dict(autopurgeSnapRetainCount=None),
            "message": "test_service_config::test_unset_parameters",
        }
    )

    expected = dict(tickTime="1111")

    with pytest.raises(AnsibleExitJson) as e:
        service_config.main()

    assert e.value.changed == True
    results = {c["name"]: c["value"] for c in e.value.config}
    assert "autopurgeSnapRetainCount" not in results
    assert expected.items() <= results.items()

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        service_config.main()

    assert e.value.changed == False
    results = {c["name"]: c["value"] for c in e.value.config}
    assert "autopurgeSnapRetainCount" not in results
    assert expected.items() <= results.items()


@pytest.mark.service_config(dict(autopurgeSnapRetainCount=7, tickTime=1111))
def test_set_parameters_with_purge(conn, module_args, zk_service_config):
    module_args(
        {
            **conn,
            "cluster": zk_service_config.cluster_ref.cluster_name,
            "service": zk_service_config.name,
            "parameters": dict(autopurgeSnapRetainCount=9),
            "purge": True,
            "message": "test_service_config::test_set_parameters_with_purge",
            # "_ansible_check_mode": True,
            # "_ansible_diff": True,
        }
    )

    expected = dict(autopurgeSnapRetainCount="9")

    with pytest.raises(AnsibleExitJson) as e:
        service_config.main()

    assert e.value.changed == True
    assert expected.items() <= {c["name"]: c["value"] for c in e.value.config}.items()

    with pytest.raises(AnsibleExitJson) as e:
        service_config.main()

    assert e.value.changed == False
    assert expected.items() <= {c["name"]: c["value"] for c in e.value.config}.items()


@pytest.mark.service_config(dict(autopurgeSnapRetainCount=8, tickTime=2222))
def test_purge_all_parameters(conn, module_args, zk_service_config):
    module_args(
        {
            **conn,
            "cluster": zk_service_config.cluster_ref.cluster_name,
            "service": zk_service_config.name,
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
