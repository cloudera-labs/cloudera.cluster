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

from collections.abc import Generator, Callable
from pathlib import Path
from time import sleep

from cm_client import (
    ApiBulkCommandList,
    ApiClient,
    ApiClusterList,
    ApiCluster,
    ApiCommand,
    ApiConfig,
    ApiHostRef,
    ApiHostRefList,
    ApiRole,
    ApiRoleConfigGroup,
    ApiRoleConfigGroupList,
    ApiRoleList,
    ApiRoleNameList,
    ApiRoleState,
    ApiService,
    ApiServiceConfig,
    ApiServiceList,
    ApiServiceState,
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
    ServicesResourceApi,
    RoleConfigGroupsResourceApi,
)
from cm_client.rest import ApiException, RESTClientObject

from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.cloudera.cluster.plugins.module_utils.parcel_utils import (
    Parcel,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    get_base_role_config_group,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    get_mgmt_roles,
)

from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleFailJson,
    AnsibleExitJson,
    provision_cm_role,
    set_cm_role_config,
    set_cm_role_config_group,
    set_role_config_group,
)


class NoHostsFoundException(Exception):
    pass


class ParcelNotFoundException(Exception):
    pass


class ZooKeeperServiceNotFoundException(Exception):
    pass


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
def module_args() -> Callable[[dict], None]:
    """Prepare module arguments"""

    def prep_args(args=dict()):
        args = json.dumps({"ANSIBLE_MODULE_ARGS": args})
        basic._ANSIBLE_ARGS = to_bytes(args)

    return prep_args


@pytest.fixture
def yaml_args() -> Callable[[dict], None]:
    """Prepare module arguments from YAML"""

    def prep_args(args: str = ""):
        output = json.dumps({"ANSIBLE_MODULE_ARGS": yaml.safe_load(args)})
        basic._ANSIBLE_ARGS = to_bytes(output)

    return prep_args


@pytest.fixture(scope="session")
def conn() -> dict:
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

        if redirect == None:
            raise Exception("Unable to establish connection to Cloudera Manager")

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
def cms_session(cm_api_client) -> Generator[ApiService]:
    """
    Provisions the Cloudera Manager Service. If the Cloudera Manager Service
    is present, will read and yield this reference. Otherwise, will
    yield a new Cloudera Manager Service, deleting it after use.

    If it does create a new Cloudera Manager Service, it will do so on the
    first available host and will auto-configure the following roles:
        - HOSTMONITOR
        - SERVICEMONITOR
        - EVENTSERVER
        - ALERTPUBLISHER

    It starts this Cloudera Manager Service, yields, and will remove this
    service if it has created it.

    Args:
        cm_api_client (ApiClient): CM API client

    Yields:
        Generator[ApiService]: Cloudera Manager Service
    """

    cms_api = MgmtServiceResourceApi(cm_api_client)

    try:
        # Return if the Cloudera Manager Service is already present
        yield cms_api.read_service()

        # Do nothing on teardown
        return
    except ApiException as ae:
        if ae.status != 404 or "Cannot find management service." not in str(ae.body):
            raise Exception(str(ae))

    service_api = MgmtServiceResourceApi(cm_api_client)
    host_api = HostsResourceApi(cm_api_client)

    host = next((h for h in host_api.read_hosts().items if not h.cluster_ref), None)

    if host is None:
        raise Exception("No available hosts to assign Cloudera Manager Service roles")

    name = "pytest-" + "".join(random.choices(string.ascii_lowercase, k=6))

    service_api.setup_cms(
        body=ApiService(
            name=name,
            type="MGMT",
            roles=[
                ApiRole(type="HOSTMONITOR"),
                ApiRole(type="SERVICEMONITOR"),
                ApiRole(type="EVENTSERVER"),
                ApiRole(type="ALERTPUBLISHER"),
            ],
        )
    )
    service_api.auto_configure()

    monitor_command(cm_api_client, service_api.start_command())

    # Return the newly-minted CMS
    yield service_api.read_service()

    # Delete the created CMS
    cms_api.delete_cms()


@pytest.fixture(scope="session")
def base_cluster(cm_api_client, cms_session) -> Generator[ApiCluster]:
    """Provision a Cloudera on premise base cluster for the session.
       If the variable 'CM_CLUSTER' is present, will attempt to read and yield
       a reference to this cluster. Otherwise, will yield a new base cluster
       with a single host, deleting the cluster once completed.

    Args:
        cm_api_client (ApiClient): CM API client

    Raises:
        Exception: _description_
        Exception: _description_
        Exception: _description_

    Yields:
        ApiCluster: The base cluster
    """

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
            cms_session.name
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
                ),
                None,
            )

            if cdh_parcel is None:
                # Roll back the cluster and then raise an error
                cluster_api.delete_cluster(cluster_name=name)
                raise ParcelNotFoundException(
                    f"CDH Version {cdh_version} not found. Please check your parcel repo configuration."
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


@pytest.fixture(scope="function")
def zk_function(cm_api_client, base_cluster, request) -> Generator[ApiService]:
    """Create a new ZooKeeper service on the provided base cluster.
    It starts this service, yields, and will remove this service if the tests
    do not.

    Args:
        cm_api_client (ApiClient): CM API client
        base_cluster (ApiCluster): Provided base cluster
        request (FixtureRequest): Fixture request

    Yields:
        Generator[ApiService]: The instantiated ZooKeeper service
    """

    service_api = ServicesResourceApi(cm_api_client)
    cm_api = ClustersResourceApi(cm_api_client)

    host = next(
        (h for h in cm_api.list_hosts(cluster_name=base_cluster.name).items), None
    )

    if host is None:
        raise NoHostsFoundException(
            "No available hosts to assign ZooKeeper service roles"
        )

    payload = ApiService(
        name="-".join(["zk", request.node.name]),
        type="ZOOKEEPER",
        roles=[
            ApiRole(
                type="SERVER",
                host_ref=ApiHostRef(host.host_id, host.hostname),
            ),
        ],
    )

    service_results = service_api.create_services(
        cluster_name=base_cluster.name, body=ApiServiceList(items=[payload])
    )

    first_run_cmd = service_api.first_run(
        cluster_name=base_cluster.name,
        service_name=service_results.items[0].name,
    )

    monitor_command(cm_api_client, first_run_cmd)

    zk_service = service_api.read_service(
        cluster_name=base_cluster.name, service_name=service_results.items[0].name
    )

    yield zk_service

    service_api.delete_service(
        cluster_name=base_cluster.name,
        service_name=zk_service.name,
    )


@pytest.fixture(scope="session")
def zk_session(cm_api_client, base_cluster) -> Generator[ApiService]:
    """Create a new ZooKeeper service on the provided base cluster.
    It starts this service, yields, and will remove this service if the tests
    do not.

    Args:
        cm_api_client (ApiClient): CM API client
        base_cluster (ApiCluster): Provided base cluster

    Yields:
        Generator[ApiService]: ZooKeeper service
    """

    service_api = ServicesResourceApi(cm_api_client)
    cm_api = ClustersResourceApi(cm_api_client)

    host = next(
        (h for h in cm_api.list_hosts(cluster_name=base_cluster.name).items), None
    )

    if host is None:
        raise NoHostsFoundException(
            "No available hosts to assign ZooKeeper service roles"
        )

    payload = ApiService(
        name="zk-session",
        type="ZOOKEEPER",
        roles=[
            ApiRole(
                type="SERVER",
                host_ref=ApiHostRef(host.host_id, host.hostname),
            ),
        ],
    )

    service_results = service_api.create_services(
        cluster_name=base_cluster.name, body=ApiServiceList(items=[payload])
    )

    first_run_cmd = service_api.first_run(
        cluster_name=base_cluster.name,
        service_name=service_results.items[0].name,
    )

    monitor_command(cm_api_client, first_run_cmd)

    zk_service = service_api.read_service(
        cluster_name=base_cluster.name, service_name=service_results.items[0].name
    )

    yield zk_service

    service_api.delete_service(
        cluster_name=base_cluster.name,
        service_name=zk_service.name,
    )


@pytest.fixture(scope="session")
def cms(cm_api_client: ApiClient, request) -> Generator[ApiService]:
    """Provisions Cloudera Manager Service. If the Cloudera Manager Service
       is present, will read and yield this reference. Otherwise, will
       yield a new Cloudera Manager Service, deleting it after use.

       NOTE! A new Cloudera Manager Service will _not_ be provisioned if
       there are any existing clusters within the deployment! Therefore,
       you must only run this fixture to provision a net-new Cloudera Manager
       Service on a bare deployment, i.e. Cloudera Manager and hosts only.

    Args:
        cm_api_client (ApiClient): _description_
        request (_type_): _description_

    Raises:
        Exception: _description_

    Yields:
        Generator[ApiService]: _description_
    """

    cms_api = MgmtServiceResourceApi(cm_api_client)

    # Return if the Cloudera Manager Service is already present
    try:
        yield cms_api.read_service()
        return
    except ApiException as ae:
        if ae.status != 404 or "Cannot find management service." not in str(ae.body):
            raise Exception(str(ae))

    # Provision the Cloudera Manager Service
    service = ApiService(
        name=request.fixturename,
        type="MGMT",
    )

    cm_service = cms_api.setup_cms(body=service)

    # Do not set up any roles -- just the CMS service itself
    # cms_api.auto_assign_roles()

    yield cm_service

    cms_api.delete_cms()


@pytest.fixture(scope="function")
def cms_cleared(cm_api_client) -> Generator[None]:
    """Clears any existing Cloudera Manager Service, yields, and upon
       return, removes any new service and reinstates the existing service,
       if present.

    Args:
        cm_api_client (_type_): _description_

    Raises:
        ae: _description_

    Yields:
        Generator[None]: _description_
    """
    service_api = MgmtServiceResourceApi(cm_api_client)
    rcg_api = MgmtRoleConfigGroupsResourceApi(cm_api_client)
    role_api = MgmtRolesResourceApi(cm_api_client)

    pre_service = None

    try:
        pre_service = service_api.read_service()
    except ApiException as ae:
        if ae.status != 404:
            raise ae

    if pre_service is not None:
        # Get the current state
        pre_service.config = service_api.read_service_config()

        # Get the role config groups' state
        if pre_service.role_config_groups is not None:
            for rcg in pre_service.role_config_groups:
                rcg.config = rcg_api.read_config(rcg.name)

        # Get each of its roles' state
        if pre_service.roles is not None:
            for r in pre_service.roles:
                r.config = role_api.read_role_config(role_name=r.name)

        # Remove the prior CMS
        service_api.delete_cms()

    # Yield now that the prior CMS has been removed
    yield

    # Remove any created CMS
    try:
        service_api.delete_cms()
    except ApiException as ae:
        if ae.status != 404:
            raise ae

    # Reinstate the prior CMS
    if pre_service is not None:
        service_api.setup_cms(body=pre_service)
        if pre_service.maintenance_mode:
            maintenance_cmd = service_api.enter_maintenance_mode()
            monitor_command(api_client=cm_api_client, command=maintenance_cmd)
        if pre_service.service_state in [
            ApiServiceState.STARTED,
            ApiServiceState.STARTING,
        ]:
            restart_cmd = service_api.restart_command()
            monitor_command(api_client=cm_api_client, command=restart_cmd)


@pytest.fixture(scope="function")
def cms_auto(cm_api_client, cms_cleared) -> Generator[ApiService]:
    """Create a new Cloudera Manager Service on the first available host and auto-configures
    the following roles:
         - HOSTMONITOR
         - SERVICEMONITOR
         - EVENTSERVER
         - ALERTPUBLISHER

    It starts this Cloudera Manager Service, yields, and will remove this service if the tests
    do not. (This fixture delegates to the 'cms_cleared' fixture.)

    Args:
        cm_api_client (_type_): _description_
        cms_cleared (_type_): _description_

    Yields:
        Generator[ApiService]: _description_
    """
    service_api = MgmtServiceResourceApi(cm_api_client)
    host_api = HostsResourceApi(cm_api_client)

    host = next((h for h in host_api.read_hosts().items if not h.cluster_ref), None)

    if host is None:
        raise Exception("No available hosts to assign Cloudera Manager Service roles")

    service_api.setup_cms(
        body=ApiService(
            type="MGMT",
            roles=[
                ApiRole(type="HOSTMONITOR"),
                ApiRole(type="SERVICEMONITOR"),
                ApiRole(type="EVENTSERVER"),
                ApiRole(type="ALERTPUBLISHER"),
            ],
        )
    )
    service_api.auto_configure()

    monitor_command(cm_api_client, service_api.start_command())

    yield service_api.read_service()


@pytest.fixture(scope="function")
def cms_auto_no_start(cm_api_client, cms_cleared) -> Generator[ApiService]:
    """Create a new Cloudera Manager Service on the first available host and auto-configures
    the following roles:
         - HOSTMONITOR
         - SERVICEMONITOR
         - EVENTSERVER
         - ALERTPUBLISHER

    It does not start this Cloudera Manager Service, yields, and will remove this service if
    the tests do not. (This fixture delegates to the 'cms_cleared' fixture.)

    Args:
        cm_api_client (_type_): _description_
        cms_cleared (_type_): _description_

    Yields:
        Generator[ApiService]: _description_
    """
    service_api = MgmtServiceResourceApi(cm_api_client)
    host_api = HostsResourceApi(cm_api_client)

    host = next((h for h in host_api.read_hosts().items if not h.cluster_ref), None)

    if host is None:
        raise Exception("No available hosts to assign Cloudera Manager Service roles")

    service_api.setup_cms(
        body=ApiService(
            type="MGMT",
            roles=[
                ApiRole(type="HOSTMONITOR"),
                ApiRole(type="SERVICEMONITOR"),
                ApiRole(type="EVENTSERVER"),
                ApiRole(type="ALERTPUBLISHER"),
            ],
        )
    )
    service_api.auto_configure()

    yield service_api.read_service()


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


@pytest.fixture(scope="function")
def host_monitor(cm_api_client, cms, request) -> Generator[ApiRole]:
    api = MgmtRolesResourceApi(cm_api_client)

    hm = next(
        iter([r for r in api.read_roles().items if r.type == "HOSTMONITOR"]), None
    )

    if hm is not None:
        yield hm
    else:
        host_api = HostsResourceApi(cm_api_client)
        host = next((h for h in host_api.read_hosts().items if not h.cluster_ref), None)

        if host is None:
            raise Exception(
                "No available hosts to assign Cloudera Manager Service role"
            )
        else:
            name = Path(request.fixturename).stem
            yield from provision_cm_role(
                cm_api_client, name, "HOSTMONITOR", host.host_id
            )


@pytest.fixture(scope="function")
def host_monitor_config(cm_api_client, host_monitor, request) -> Generator[ApiRole]:
    marker = request.node.get_closest_marker("role_config")

    if marker is None:
        raise Exception("No role_config marker found.")

    yield from set_cm_role_config(
        api_client=cm_api_client,
        role=host_monitor,
        params=marker.args[0],
        message=f"{Path(request.node.parent.name).stem}::{request.node.name}",
    )


@pytest.fixture(scope="function")
def host_monitor_role_group_config(
    cm_api_client, host_monitor, request
) -> Generator[ApiRoleConfigGroup]:
    """Configures the base Role Config Group for the Host Monitor role of a Cloudera Manager Service."""
    marker = request.node.get_closest_marker("role_config_group")

    if marker is None:
        raise Exception("No 'role_config_group' marker found.")

    rcg_api = MgmtRoleConfigGroupsResourceApi(cm_api_client)
    rcg = rcg_api.read_role_config_group(
        host_monitor.role_config_group_ref.role_config_group_name
    )
    rcg.config = rcg_api.read_config(role_config_group_name=rcg.name)

    yield from set_cm_role_config_group(
        api_client=cm_api_client,
        role_config_group=rcg,
        update=marker.args[0],
        message=f"{Path(request.node.parent.name).stem}::{request.node.name}",
    )


@pytest.fixture(scope="function")
def host_monitor_cleared(cm_api_client, cms) -> Generator[None]:
    role_api = MgmtRolesResourceApi(cm_api_client)
    role_cmd_api = MgmtRoleCommandsResourceApi(cm_api_client)

    # Check for existing management role
    pre_role = next(
        iter([r for r in get_mgmt_roles(cm_api_client, "HOSTMONITOR").items]), None
    )

    if pre_role is not None:
        # Get the current state
        pre_role.config = role_api.read_role_config(role_name=pre_role.name)

        # Remove the prior role
        role_api.delete_role(role_name=pre_role.name)

    # Yield now that the role has been removed
    yield

    # Reinstate the previous role
    if pre_role is not None:
        role_api.create_roles(body=ApiRoleList(items=[pre_role]))
        if pre_role.maintenance_mode:
            role_api.enter_maintenance_mode(pre_role.name)
        if pre_role.role_state in [ApiRoleState.STARTED, ApiRoleState.STARTING]:
            restart_cmds = role_cmd_api.restart_command(
                body=ApiRoleNameList(items=[pre_role.name])
            )
            handle_commands(api_client=cm_api_client, commands=restart_cmds)


@pytest.fixture(scope="function")
def host_monitor_state(
    cm_api_client, host_monitor, request
) -> Generator[ApiRoleConfigGroup]:
    marker = request.node.get_closest_marker("role_state")

    if marker is None:
        raise Exception("No 'role_state' marker found.")

    role_state = marker.args[0]

    role_api = MgmtRolesResourceApi(cm_api_client)
    cmd_api = MgmtRoleCommandsResourceApi(cm_api_client)

    # Get the current state
    pre_role = role_api.read_role(host_monitor.name)

    # Set the role state
    if pre_role.role_state != role_state:
        if role_state in [ApiRoleState.STARTED]:
            handle_commands(
                api_client=cm_api_client,
                commands=cmd_api.start_command(
                    body=ApiRoleNameList(items=[host_monitor.name])
                ),
            )
        elif role_state in [ApiRoleState.STOPPED]:
            handle_commands(
                api_client=cm_api_client,
                commands=cmd_api.stop_command(
                    body=ApiRoleNameList(items=[host_monitor.name])
                ),
            )

    # Yield the role
    current_role = role_api.read_role(host_monitor.name)
    current_role.config = role_api.read_role_config(host_monitor.name)
    yield current_role

    # Retrieve the test changes
    post_role = role_api.read_role(role_name=host_monitor.name)
    post_role.config = role_api.read_role_config(role_name=host_monitor.name)

    # Reset state
    if pre_role.role_state != post_role.role_state:
        if pre_role.role_state in [ApiRoleState.STARTED]:
            handle_commands(
                api_client=cm_api_client,
                commands=cmd_api.start_command(
                    body=ApiRoleNameList(items=[host_monitor.name])
                ),
            )
        elif pre_role.role_state in [ApiRoleState.STOPPED]:
            handle_commands(
                api_client=cm_api_client,
                commands=cmd_api.stop_command(
                    body=ApiRoleNameList(items=[host_monitor.name])
                ),
            )


@pytest.fixture(scope="function")
def zk_role_config_group(
    cm_api_client, zk_session, request
) -> Generator[ApiRoleConfigGroup]:
    """
    Creates or updates a Role Config Group of a ZooKeeper service, i.e. a SERVER role type group.
    """
    marker = request.node.get_closest_marker("role_config_group")

    if marker is None:
        raise Exception("No 'role_config_group' marker found.")

    update_rcg = marker.args[0]

    rcg_api = RoleConfigGroupsResourceApi(cm_api_client)

    rcg = None
    if update_rcg.name is not None:
        # If it exists, update it
        try:
            rcg = rcg_api.read_role_config_group(
                cluster_name=zk_session.cluster_ref.cluster_name,
                service_name=zk_session.name,
                role_config_group_name=update_rcg.name,
            )
        except ApiException as ex:
            if ex.status != 404:
                raise ex

        # If it doesn't exist, create, yield, and destroy
        if rcg is None:
            rcg = rcg_api.create_role_config_groups(
                cluster_name=zk_session.cluster_ref.cluster_name,
                service_name=zk_session.name,
                body=ApiRoleConfigGroupList(items=[update_rcg]),
            ).items[0]

            yield rcg

            try:
                rcg_api.delete_role_config_group(
                    cluster_name=zk_session.cluster_ref.cluster_name,
                    service_name=zk_session.name,
                    role_config_group_name=rcg.name,
                )
            except ApiException as ex:
                if ex.status != 404:
                    raise ex

            return
    else:
        rcg = get_base_role_config_group(
            api_client=cm_api_client,
            cluster_name=zk_session.cluster_ref.cluster_name,
            service_name=zk_session.name,
            role_type="SERVER",
        )

    rcg.config = rcg_api.read_config(
        cluster_name=zk_session.cluster_ref.cluster_name,
        service_name=zk_session.name,
        role_config_group_name=rcg.name,
    )

    yield from set_role_config_group(
        api_client=cm_api_client,
        cluster_name=zk_session.cluster_ref.cluster_name,
        service_name=zk_session.name,
        role_config_group=rcg,
        update=update_rcg,
        message=f"{Path(request.node.parent.name).stem}::{request.node.name}",
    )


def handle_commands(api_client: ApiClient, commands: ApiBulkCommandList):
    if commands.errors:
        error_msg = "\n".join(commands.errors)
        raise Exception(error_msg)

    for cmd in commands.items:
        # Serial monitoring
        monitor_command(api_client, cmd)


def monitor_command(
    api_client: ApiClient, command: ApiCommand, polling: int = 120, delay: int = 10
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
