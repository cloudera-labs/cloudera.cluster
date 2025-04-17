#!/usr/bin/python
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

DOCUMENTATION = r"""
module: service_info
short_description: Retrieve information about the services of cluster
description:
  - Gather information about services of a CDP cluster.
author:
  - "Webster Mudge (@wmudge)"
options:
  cluster:
    description:
      - The cluster to examine.
    type: str
    required: yes
    aliases:
      - cluster_name
  name:
    description:
      - A service to retrieve.
      - If absent, the module will return all services.
    type: str
    aliases:
      - service_name
      - service
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  platform:
    platforms: all
requirements:
  - cm-client
seealso:
  - module: cloudera.cluster.service
"""

EXAMPLES = r"""
- name: Gather details of the services of a cluster
  cloudera.cluster.service_info:
    host: "example.cloudera.host"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster

- name: Gather the details with additional healthcheck information for a service
  cloudera.cluster.service_info:
    host: "example.cloudera.host"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: ecs
    view: healthcheck
"""

RETURN = r"""
services:
  description: Details about the services of a cluster.
  type: list
  elements: dict
  contains:
    name:
      description: The cluster service name.
      type: str
      returned: always
    type:
      description: The cluster service type.
      type: str
      returned: always
      sample:
        - HDFS
        - HBASE
        - ECS
    cluster_name:
      description: The name of the cluster, which uniquely identifies it in a Cloudera Manager installation.
      type: str
      returned: always
    service_state:
      description: State of the service.
      type: str
      returned: always
      sample:
        - HISTORY_NOT_AVAILABLE
        - UNKNOWN
        - STARTING
        - STARTED
        - STOPPING
        - STOPPED
        - NA
    health_summary:
      description: The high-level health status of the service.
      type: str
      returned: always
      sample:
        - DISABLED
        - HISTORY_NOT_AVAILABLE
        - NOT_AVAILABLE
        - GOOD
        - CONCERNING
        - BAD
    config_staleness_status:
      description: Status of configuration staleness for the service.
      type: str
      returned: always
      sample:
        - FRESH
        - STALE_REFRESHABLE
        - STALE
    client_config_staleness_status:
      description: Status of the client configuration for the service.
      type: str
      returned: always
      sample:
        - FRESH
        - STALE_REFRESHABLE
        - STALE
    health_checks:
      description: Lists all available health checks for Cloudera Manager Service.
      type: list
      elements: dict
      returned: when supported
      contains:
        name:
          description: Unique name of this health check.
          type: str
          returned: always
        summary:
          description: The high-level health status of the health check.
          type: str
          returned: always
          sample:
            - DISABLED
            - HISTORY_NOT_AVAILABLE
            - NOT_AVAILABLE
            - GOOD
            - CONCERNING
            - BAD
        explanation:
          description: The explanation of this health check.
          type: str
          returned: when supported
        suppressed:
          description:
            - Whether this health check is suppressed.
            - A suppressed health check is not considered when computing the service's overall health.
          type: bool
          returned: when supported
    maintenance_mode:
      description: Whether the service is in maintenance mode.
      type: bool
      returned: when supported
    maintenance_owners:
      description: The list of objects that trigger this service to be in maintenance mode.
      type: list
      elements: str
      returned: when supported
      sample:
        - CLUSTER
        - SERVICE
        - ROLE
        - HOST
        - CONTROL_PLANE
    display_name:
      description: The display name for the service that is shown in the Cloudera Manager UI.
      type: str
      returned: when supported
    tags:
      description: The dictionary of tags for the service.
      type: dict
      returned: when supported
    service_version:
      description: Version of the service.
      type: str
      returned: when supported
    config:
      description: Service-wide configuration details about a cluster service.
      type: dict
      returned: when supported
    role_config_groups:
      description: List of base and custom role config groups for the cluster service.
      type: list
      elements: dict
      contains:
        name:
          description:
            - The unique name of this role config group.
          type: str
          returned: always
        role_type:
          description:
            - The type of the roles in this group.
          type: str
          returned: always
        base:
          description:
            - Flag indicating whether this is a base group.
          type: bool
          returned: always
        display_name:
          description:
            - A user-friendly name of the role config group, as would have been shown in the web UI.
          type: str
          returned: when supported
        config:
          description: Set of configurations for the role config group.
          type: dict
          returned: when supported
      returned: when supported
    roles:
      description: List of provisioned role instances on cluster hosts for the cluster service.
      type: list
      elements: dict
      contains:
        name:
          description: The cluster service role name.
          type: str
          returned: always
        type:
          description: The cluster service role type.
          type: str
          returned: always
          sample:
            - NAMENODE
            - DATANODE
            - TASKTRACKER
        host_id:
          description: The unique ID of the cluster host.
          type: str
          returned: always
        hostname:
          description: The hostname of the cluster host.
          type: str
          returned: always
        role_state:
          description: State of the cluster service role.
          type: str
          returned: always
          sample:
            - HISTORY_NOT_AVAILABLE
            - UNKNOWN
            - STARTING
            - STARTED
            - STOPPING
            - STOPPED
            - NA
        commission_state:
          description: Commission state of the cluster service role.
          type: str
          returned: always
        health_summary:
          description: The high-level health status of the cluster service role.
          type: str
          returned: always
          sample:
            - DISABLED
            - HISTORY_NOT_AVAILABLE
            - NOT_AVAILABLE
            - GOOD
            - CONCERNING
            - BAD
        config_staleness_status:
          description: Status of configuration staleness for the cluster service role.
          type: str
          returned: always
          sample:
            - FRESH
            - STALE_REFRESHABLE
            - STALE
        health_checks:
          description: Lists all available health checks for cluster service role.
          type: list
          elements: dict
          returned: when supported
          contains:
            name:
              description: Unique name of this health check.
              type: str
              returned: always
            summary:
              description: The high-level health status of the health check.
              type: str
              returned: always
              sample:
                - DISABLED
                - HISTORY_NOT_AVAILABLE
                - NOT_AVAILABLE
                - GOOD
                - CONCERNING
                - BAD
            explanation:
              description: The explanation of this health check.
              type: str
              returned: when supported
            suppressed:
              description:
                - Whether this health check is suppressed.
                - A suppressed health check is not considered when computing the role's overall health.
              type: bool
              returned: when supported
        maintenance_mode:
          description: Whether the cluster service role is in maintenance mode.
          type: bool
          returned: when supported
        maintenance_owners:
          description: The list of objects that trigger this service to be in maintenance mode.
          type: list
          elements: str
          returned: when supported
          sample:
            - CLUSTER
            - SERVICE
            - ROLE
            - HOST
            - CONTROL_PLANE
        role_config_group_name:
          description: The name of the cluster service role config group, which uniquely identifies it in a Cloudera Manager installation.
          type: str
          returned: when supported
        config:
          description: Set of role configurations for the cluster service role.
          type: dict
          returned: when supported
        tags:
          description: The dictionary of tags for the cluster service role.
          type: dict
          returned: when supported
        zoo_keeper_server_mode:
          description:
            - The Zookeeper server mode for this cluster service role.
            - Note that for non-Zookeeper Server roles, this will be C(null).
          type: str
          returned: when supported
      returned: when supported
"""

from cm_client import (
    ClustersResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.service_utils import (
    parse_service_result,
    read_service,
    read_services,
)


class ClusterServiceInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClusterServiceInfo, self).__init__(module)

        # Set the parameters
        self.cluster = self.get_param("cluster")
        self.name = self.get_param("name")
        self.view = self.get_param("view")

        # Initialize the return values
        self.output = []

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        try:
            ClustersResourceApi(self.api_client).read_cluster(self.cluster)
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg="Cluster does not exist: " + self.cluster)
            else:
                raise ex

        service_api = ServicesResourceApi(self.api_client)

        if self.name:
            try:
                self.output.append(
                    parse_service_result(
                        read_service(
                            api_client=self.api_client,
                            cluster_name=self.cluster,
                            service_name=self.name,
                        )
                    )
                )
            except ApiException as e:
                if e.status != 404:
                    raise e
        else:
            self.output = [
                parse_service_result(s)
                for s in read_services(
                    api_client=self.api_client,
                    cluster_name=self.cluster,
                )
            ]


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            name=dict(aliases=["service_name", "service"]),
        ),
        supports_check_mode=True,
    )

    result = ClusterServiceInfo(module)

    output = dict(
        changed=False,
        services=result.output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
