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

import json
import os
import pytest
import random
import string
import sys
import yaml

from pathlib import Path

from cm_client import (
    ApiClient,
    ApiClusterList,
    ApiCluster,
    ApiHostRef,
    ApiHostRefList,
    ClustersResourceApi,
    Configuration,
    HostsResourceApi,
    ParcelResourceApi,
    ParcelsResourceApi,
)
from cm_client.rest import ApiException, RESTClientObject

from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.cloudera.cluster.plugins.module_utils.parcel_utils import (
    Parcel,
)

from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleFailJson,
    AnsibleExitJson,
)


@pytest.fixture(autouse=True)
def skip_python():
    if sys.version_info < (3, 6):
        pytest.skip(
            "Skipping on Python %s. cloudera.cloud supports Python 3.6 and higher."
            % sys.version
        )


@pytest.fixture(autouse=True)
def patch_module(monkeypatch):
    """Patch AnsibleModule to raise exceptions on success and failure"""

    def exit_json(*args, **kwargs):
        if "changed" not in kwargs:
            kwargs["changed"] = False
        raise AnsibleExitJson(kwargs)

    def fail_json(*args, **kwargs):
        kwargs["failed"] = True
        raise AnsibleFailJson(kwargs)

    monkeypatch.setattr(basic.AnsibleModule, "exit_json", exit_json)
    monkeypatch.setattr(basic.AnsibleModule, "fail_json", fail_json)


@pytest.fixture
def module_args():
    """Prepare module arguments"""

    def prep_args(args=dict()):
        args = json.dumps({"ANSIBLE_MODULE_ARGS": args})
        basic._ANSIBLE_ARGS = to_bytes(args)

    return prep_args


@pytest.fixture
def yaml_args():
    """Prepare module arguments from YAML"""

    def prep_args(args: str = ""):
        output = json.dumps({"ANSIBLE_MODULE_ARGS": yaml.safe_load(args)})
        basic._ANSIBLE_ARGS = to_bytes(output)

    return prep_args


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
def cm_api_client(conn) -> ApiClient:
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
        url = f"{conn['host']}:{conn['port']}"

        # Handle redirects
        redirect = rest.GET(url).urllib3_response.geturl()
        if redirect != "/":
            url = redirect

        url = url.rstrip(" /")

        # Get version
        auth = config.auth_settings().get("basic")
        version = rest.GET(
            f"{url}/api/version", headers={auth["key"]: auth["value"]}
        ).data

        # Set host
        config.host = f"{url}/api/{version}"

    client = ApiClient()
    client.user_agent = "pytest"
    return client


@pytest.fixture(scope="session")
def target_cluster(cm_api_client, request):
    """Create a test cluster."""

    cluster_api = ClustersResourceApi(cm_api_client)

    if os.getenv("CM_CLUSTER_NAME", None):
        yield cluster_api.read_cluster(cluster_name=os.getenv("CM_CLUSTER_NAME"))
    else:
        if os.getenv("CDH_VERSION", None):
            cdh_version = os.getenv("CDH_VERSION")
        else:
            raise Exception(
                "No CDH_VERSION found. Please set this environment variable."
            )

        name = (
            Path(request.fixturename).stem
            + "_"
            + "".join(random.choices(string.ascii_lowercase, k=6))
        )

        parcels_api = ParcelsResourceApi(cm_api_client)
        parcel_api = ParcelResourceApi(cm_api_client)
        host_api = HostsResourceApi(cm_api_client)

        try:
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
            cdh_parcel = next(
                (
                    p
                    for p in parcels.items
                    if p.product == "CDH" and p.version.startswith(cdh_version)
                )
            )

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
