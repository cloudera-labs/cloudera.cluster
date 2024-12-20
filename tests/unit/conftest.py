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

from collections.abc import Generator
from pathlib import Path
from time import sleep

from cm_client import (
    ApiBulkCommandList,
    ApiClient,
    ApiClusterList,
    ApiCluster,
    ApiCommand,
    ApiConfig,
    ApiConfigList,
    ApiHostRef,
    ApiHostRefList,
    ApiRole,
    ApiRoleConfigGroup,
    ApiRoleNameList,
    ApiRoleState,
    ApiService,
    ApiServiceConfig,
    ClustersResourceApi,
    CommandsResourceApi,
    Configuration,
    HostsResourceApi,
    MgmtRoleCommandsResourceApi,
    MgmtRoleConfigGroupsResourceApi,
    MgmtRolesResourceApi,
    MgmtServiceResourceApi,
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
    provision_cm_role,
    set_cm_role_config_group,
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
def base_cluster(cm_api_client, request):
    """Provision a CDH Base cluster."""

    cluster_api = ClustersResourceApi(cm_api_client)

    if os.getenv("CM_CLUSTER", None):
        yield cluster_api.read_cluster(cluster_name=os.getenv("CM_CLUSTER"))
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


@pytest.fixture(scope="session")
def cms(cm_api_client, request) -> Generator[ApiService]:
    """Provisions Cloudera Manager Service."""

    api = MgmtServiceResourceApi(cm_api_client)

    # Return if the Cloudera Manager Service is already present
    try:
        yield api.read_service()
        return
    except ApiException as ae:
        if ae.status != 404 or "Cannot find management service." not in str(ae.body):
            raise Exception(str(ae))

    # Provision the Cloudera Manager Service
    service = ApiService(
        name=request.fixturename,
        type="MGMT",
    )

    yield api.setup_cms(body=service)

    api.delete_cms()


@pytest.fixture(scope="function")
def cms_config(cm_api_client, cms, request) -> Generator[ApiService]:
    """Configures service-wide configurations for the Cloudera Manager Service"""

    marker = request.node.get_closest_marker("service_config")

    if marker is None:
        raise Exception("No service_config marker found.")

    api = MgmtServiceResourceApi(cm_api_client)

    # Retrieve all of the pre-setup configurations
    pre = api.read_service_config()

    # Set the test configurations
    # Do so serially, since a failed update due to defaults (see ApiException) will cause remaining
    # configuration entries to not run. Long-term solution is to check-and-set, which is
    # what the Ansible modules do...
    for k, v in marker.args[0].items():
        try:
            api.update_service_config(
                message=f"{Path(request.node.parent.name).stem}::{request.node.name}::set",
                body=ApiServiceConfig(items=[ApiConfig(name=k, value=v)]),
            )
        except ApiException as ae:
            if ae.status != 400 or "delete with template" not in str(ae.body):
                raise Exception(str(ae))

    # Yield the Cloudera Manager Service
    yield cms

    # Retrieve all of the post-setup configurations
    post = api.read_service_config()

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

    api.update_service_config(
        message=f"{Path(request.node.parent.name).stem}::{request.node.name}::reset",
        body=ApiServiceConfig(items=reconciled),
    )


@pytest.fixture(scope="module")
def host_monitor_role(cm_api_client, cms, request) -> Generator[ApiRole]:
    api = MgmtRolesResourceApi(cm_api_client)

    hm = next(
        iter([r for r in api.read_roles().items if r.type == "HOSTMONITOR"]), None
    )

    if hm is not None:
        yield hm
    else:
        cluster_api = ClustersResourceApi(cm_api_client)

        # Get first host of the cluster
        hosts = cluster_api.list_hosts(cluster_name=cms.cluster_ref.cluster_name)

        if not hosts.items:
            raise Exception(
                "No available hosts to assign the Cloudera Manager Service role."
            )
        else:
            name = Path(request.fixturename).stem
            yield from provision_cm_role(
                cm_api_client, name, "HOSTMONITOR", hosts.items[0].hostId
            )


@pytest.fixture(scope="function")
def host_monitor_role_group_config(
    cm_api_client, host_monitor_role, request
) -> Generator[ApiRoleConfigGroup]:
    marker = request.node.get_closest_marker("role_config_group")

    if marker is None:
        raise Exception("No 'role_config_group' marker found.")

    rcg_api = MgmtRoleConfigGroupsResourceApi(cm_api_client)

    yield from set_cm_role_config_group(
        api_client=cm_api_client,
        role_config_group=rcg_api.read_role_config_group(
            host_monitor_role.role_config_group_ref.role_config_group_name
        ),
        update=marker.args[0],
        message=f"{Path(request.node.parent.name).stem}::{request.node.name}",
    )


@pytest.fixture(scope="function")
def host_monitor_state(cm_api_client, host_monitor_role, request) -> Generator[ApiRole]:
    marker = request.node.get_closest_marker("role")

    if marker is None:
        raise Exception("No 'role' marker found.")

    role = marker.args[0]

    role_api = MgmtRolesResourceApi(cm_api_client)
    cmd_api = MgmtRoleCommandsResourceApi(cm_api_client)

    # Get the current state
    pre_role = role_api.read_role(host_monitor_role.name)
    pre_role.config = role_api.read_role_config(host_monitor_role.name)

    # Set config
    for c in role.config.items:
        try:
            role_api.update_role_config(
                role_name=host_monitor_role.name,
                message=f"{Path(request.node.parent.name).stem}::{request.node.name}::set",
                body=ApiConfigList(items=[c]),
            )
        except ApiException as ae:
            if ae.status != 400 or "delete with template" not in str(ae.body):
                raise Exception(str(ae))

    # Update maintenance
    if role.maintenance_mode:
        role_api.enter_maintenance_mode(host_monitor_role.name)
    else:
        role_api.exit_maintenance_mode(host_monitor_role.name)

    # Update state
    if role.role_state is not None:
        if role.role_state in [ApiRoleState.STARTED]:
            handle_commands(
                cmd_api.stop_command(
                    body=ApiRoleNameList(items=[host_monitor_role.name])
                )
            )
        elif role.role_state in [ApiRoleState.STOPPED]:
            handle_commands(
                cmd_api.start_command(
                    body=ApiRoleNameList(items=[host_monitor_role.name])
                )
            )

    # Yield the role
    current_role = role_api.read_role(host_monitor_role.name)
    current_role.config = role_api.read_role_config(host_monitor_role.name)
    yield current_role

    # Retrieve the test changes
    post_role = role_api.read_role(role_name=host_monitor_role.name)
    post_role.config = role_api.read_role_config(role_name=host_monitor_role.name)

    # Reset state
    if pre_role.role_state != post_role.role_state:
        if pre_role.role_state in [ApiRoleState.STARTED]:
            handle_commands(
                cmd_api.start_command(
                    body=ApiRoleNameList(items=[host_monitor_role.name])
                )
            )
        elif pre_role.role_state in [ApiRoleState.STOPPED]:
            handle_commands(
                cmd_api.stop_command(
                    body=ApiRoleNameList(items=[host_monitor_role.name])
                )
            )

    # Reset maintenance
    if pre_role.maintenance_mode != post_role.maintenance_mode:
        if pre_role.maintenance_mode:
            role_api.enter_maintenance_mode(host_monitor_role.name)
        else:
            role_api.exit_maintenance_mode(host_monitor_role.name)

    # Reset config
    pre_role_config_set = set([c.name for c in pre_role.config.items])

    reconciled = pre_role.config.items.copy()
    config_reset = [
        c for c in post_role.config.items if c.name not in pre_role_config_set
    ]
    reconciled.extend([ApiConfig(c.name, None) for c in config_reset])

    role_api.update_role_config(
        role_name=host_monitor_role.name,
        message=f"{Path(request.node.parent.name).stem}::{request.node.name}::reset",
        body=ApiConfigList(items=reconciled),
    )


def handle_commands(api_client: ApiClient, commands: ApiBulkCommandList):
    if commands.errors:
        error_msg = "\n".join(commands.errors)
        raise Exception(error_msg)

    for cmd in commands.items:
        # Serial monitoring
        monitor_command(api_client, cmd)


def monitor_command(
    api_client: ApiClient, command: ApiCommand, polling: int = 10, delay: int = 15
):
    poll_count = 0
    while command.active:
        if poll_count > polling:
            raise Exception("Command timeout: " + str(command.id))
        sleep(delay)
        poll_count += 1
        command = CommandsResourceApi(api_client).read_command(command.id)
    if not command.success:
        raise Exception(command.result_message)
