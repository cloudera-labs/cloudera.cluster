# -*- coding: utf-8 -*-
#
# Copyright 2024 Cloudera, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections.abc import Generator
from time import sleep

from cm_client import (
    ApiClient,
    ApiCluster,
    ApiCommand,
    ApiConfig,
    ApiService,
    ApiServiceConfig,
    ApiServiceList,
    ClustersResourceApi,
    CommandsResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException


class AnsibleExitJson(Exception):
    """Exception class to be raised by module.exit_json and caught by the test case"""

    def __init__(self, kwargs):
        super(AnsibleExitJson, self).__init__(
            kwargs.get("msg", "General module success")
        )
        self.__dict__.update(kwargs)


class AnsibleFailJson(Exception):
    """Exception class to be raised by module.fail_json and caught by the test case"""

    def __init__(self, kwargs):
        super(AnsibleFailJson, self).__init__(
            kwargs.get("msg", "General module failure")
        )
        self.__dict__.update(kwargs)


def wait_for_command(
    api_client: ApiClient, command: ApiCommand, polling: int = 120, delay: int = 5
):
    """Polls Cloudera Manager to wait for a Command to complete."""

    poll_count = 0
    while command.active:
        if poll_count > polling:
            raise Exception("CM command timeout")
        sleep(delay)
        poll_count += 1
        command = CommandsResourceApi(api_client).read_command(command.id)
    if not command.success:
        raise Exception(f"CM command [{command.id}] failed: {command.result_message}")


def provision_service(
    api_client: ApiClient, cluster: ApiCluster, service_name: str, service_type: str
) -> Generator[ApiService]:
    """Provisions a new cluster service as a generator.
       Use with 'yield from' to delegate within a pytest fixture.

    Args:
        api_client (ApiClient): _description_
        cluster (ApiCluster): _description_
        service_name (dict): _description_
        service_type (str): _description_

    Raises:
        Exception: _description_

    Yields:
        ApiService: _description_
    """

    api = ServicesResourceApi(api_client)
    cluster_api = ClustersResourceApi(api_client)

    service = ApiService(
        name=service_name,
        type=service_type,
    )

    api.create_services(cluster_name=cluster.name, body=ApiServiceList(items=[service]))
    cluster_api.auto_assign_roles(cluster_name=cluster.name)

    # configure = cluster_api.auto_configure(cluster_name=target_cluster.name)
    wait_for_command(
        api_client,
        api.first_run(cluster_name=cluster.name, service_name=service_name),
    )

    yield api.read_service(cluster_name=cluster.name, service_name=service_name)

    api.delete_service(cluster_name=cluster.name, service_name=service_name)


def service_wide_config(
    api_client: ApiClient, service: ApiService, params: dict, message: str
) -> Generator[ApiService]:
    """Update a service-wide configuration for a given service. Yields the
       service, resetting the configuration to its prior state. Use with
       'yield from' within a pytest fixture.

    Args:
        api_client (ApiClient): _description_
        service (ApiService): _description_
        params (dict): _description_
        message (str): _description_

    Raises:
        Exception: _description_

    Yields:
        ApiService: _description_
    """
    service_api = ServicesResourceApi(api_client)

    # Retrieve all of the pre-setup configurations
    pre = service_api.read_service_config(
        cluster_name=service.cluster_ref.cluster_name,
        service_name=service.name,
    )

    # Set the test configurations
    # Do so serially, since a failed update due to defaults (see ApiException) will cause remaining
    # configuration entries to not run. Long-term solution is to check-and-set, which is
    # what the Ansible modules do...
    for k, v in params.items():
        try:
            service_api.update_service_config(
                cluster_name=service.cluster_ref.cluster_name,
                service_name=service.name,
                message=f"{message}::set",
                body=ApiServiceConfig(items=[ApiConfig(name=k, value=v)]),
            )
        except ApiException as ae:
            if ae.status != 400 or "delete with template" not in str(ae.body):
                raise Exception(str(ae))

    # Yield the targeted service
    yield service

    # Retrieve all of the post-setup configurations
    post = service_api.read_service_config(
        cluster_name=service.cluster_ref.cluster_name,
        service_name=service.name,
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
        cluster_name=service.cluster_ref.cluster_name,
        service_name=service.name,
        message=f"{message}::reset",
        body=ApiServiceConfig(items=reconciled),
    )
