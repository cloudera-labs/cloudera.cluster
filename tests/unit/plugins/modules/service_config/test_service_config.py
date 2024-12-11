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
from time import sleep

from cm_client import (
    ApiClient,
    ApiClusterList,
    ApiCluster,
    ApiCommand,
    ApiConfig,
    ApiHostRef,
    ApiHostRefList,
    ApiService,
    ApiServiceConfig,
    ApiServiceList,
    ClustersResourceApi,
    CommandsResourceApi,
    Configuration,
    HostsResourceApi,
    ParcelResourceApi,
    ParcelsResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException, RESTClientObject

from ansible_collections.cloudera.cluster.plugins.modules import service_config
from ansible_collections.cloudera.cluster.plugins.module_utils.parcel_utils import (
    Parcel,
)

from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def conn():
    conn = dict(username=os.getenv("CM_USERNAME"), password=os.getenv("CM_PASSWORD"))

    if os.getenv("CM_HOST", None):
        conn.update(host=os.getenv("CM_HOST"))

    if os.getenv("CM_PORT", None):
        conn.update(port=os.getenv("CM_PORT"))

    if os.getenv("CM_ENDPOINT", None):
        conn.update(url=os.getenv("CM_ENDPOINT"))

    if os.getenv("CM_PROXY", None):
        conn.update(proxy=os.getenv("CM_PROXY"))

    return {
        **conn,
        "verify_tls": "no",
        "debug": "no",
    }


@pytest.fixture(scope="session")
def cm_api_client(conn):
    """Create a Cloudera Manager API client, resolving HTTP/S and version URL.

    Args:
        conn (dict): Connection details

    Returns:
        ApiClient: Cloudera Manager API client
    """
    config = Configuration()

    config.username = conn["username"]
    config.password = conn["password"]

    if "url" in conn:
        config.host = str(conn["url"]).rstrip(" /")
    else:
        rest = RESTClientObject()

        # Handle redirects
        url = rest.GET(conn["host"]).urllib3_response.geturl()

        # Get version
        auth = config.auth_settings().get("basic")
        version = rest.GET(
            f"{url}api/version", headers={auth["key"]: auth["value"]}
        ).data

        # Set host
        config.host = f"{url}api/{version}"

    client = ApiClient()
    client.user_agent = "pytest"
    return client


@pytest.fixture(scope="session")
def target_cluster(cm_api_client, request):
    """Create a 7.1.9 test cluster."""

    name = (
        Path(request.fixturename).stem
        + "_"
        + "".join(random.choices(string.ascii_lowercase, k=6))
    )
    cdh_version = "7.1.9"

    cluster_api = ClustersResourceApi(cm_api_client)
    parcels_api = ParcelsResourceApi(cm_api_client)
    parcel_api = ParcelResourceApi(cm_api_client)
    host_api = HostsResourceApi(cm_api_client)

    try:
        # TODO Query for the latest version available - is this possible?

        # Create the initial cluster
        config = ApiCluster(
            name=name,
            full_version=cdh_version,
        )

        cluster_api.create_clusters(body=ApiClusterList(items=[config]))

        # Get first free host and assign to the cluster
        all_hosts = host_api.read_hosts()
        host = next((h for h in all_hosts.items if not h.cluster_ref), None)

        if host is None:
            # Roll back the cluster and then raise an error
            cluster_api.delete_cluster(cluster_name=name)
            raise Exception("No available hosts to allocate to new cluster")
        else:
            cluster_api.add_hosts(
                cluster_name=name,
                body=ApiHostRefList(items=[ApiHostRef(host_id=host.host_id)]),
            )

        # Find the first CDH parcel version and activate it
        parcels = parcels_api.read_parcels(cluster_name=name)
        cdh_parcel = next((p for p in parcels.items if p.product == "CDH"))

        parcel = Parcel(
            parcel_api=parcel_api,
            product=cdh_parcel.product,
            version=cdh_parcel.version,
            cluster=name,
        )

        parcel.activate()

        # Reread and return the cluster
        yield cluster_api.read_cluster(cluster_name=name)

        # Deprovision the cluster
        cluster_api.delete_cluster(cluster_name=name)
    except ApiException as ae:
        raise Exception(str(ae))


def wait_for_command(
    api_client: ApiClient, command: ApiCommand, polling: int = 120, delay: int = 5
):
    poll_count = 0
    while command.active:
        if poll_count > polling:
            raise Exception("CM command timeout")
        sleep(delay)
        poll_count += 1
        command = CommandsResourceApi(api_client).read_command(command.id)
    if not command.success:
        raise Exception(f"CM command [{command.id}] failed: {command.result_message}")


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
