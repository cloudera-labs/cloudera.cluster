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

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)

from cm_client import ApiService, ServicesResourceApi
from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: cluster_service_info
short_description: Retrieve information about the services of cluster
description:
  - Gather information about services of a CDP cluster.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
options:
  cluster:
    description:
      - The cluster to examine.
    type: str
    required: yes
    aliases:
      - cluster_name
  service:
    description:
      - A service to retrieve.
      - If absent, the module will return all services.
    type: str
    aliases:
      - service_name
      - name
  view:
    description:
      - The view to materialize.
      - C(healthcheck) is the equivalent to I(full_with_health_check_explanation).
      - C(redacted) is the equivalent to I(export_redacted).
    type: str
    default: summary
    choices:
        - summary
        - full
        - healthcheck
        - export
        - redacted
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
"""

EXAMPLES = r"""
---
- name: Gather details of the services of a cluster
  cloudera.cluster.cluster_service_info:
    host: "example.cloudera.host"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
  
- name: Gather the details with additional healthcheck information for a service
  cloudera.cluster.cluster_service_info:
    host: "example.cloudera.host"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: ecs
    view: healthcheck
"""

RETURN = r"""
---
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
    cluster_ref:
      description: The associated cluster reference.
      type: dict
      returned: always
      contains:
        clusterName:
          description: The name of the cluster, which uniquely identifies it in a Cloudera Manager installation.
          type: str
          returned: always
        displayName:
          description: The display name of the cluster.
          type: str
          returned: when supported
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
      description: List of tags for the service.
      type: list
      elements: str
      returned: when supported
    service_version:
      description: Version of the service.
      type: str
      returned: when supported
"""

SERVICE_OUTPUT = [
    "client_config_staleness_status",
    "cluster_ref",
    "config_staleness_status",
    "display_name",
    "health_checks",
    "health_summary",
    "maintenance_mode",
    "maintenance_owners",
    "name",
    "service_state",
    "service_version",
    "tags",
    "type",
]


def parse_service_result(service: ApiService) -> dict:
    rendered = service.to_dict()
    return {k: rendered[k] for k in SERVICE_OUTPUT}


class ClusterServiceInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClusterServiceInfo, self).__init__(module)

        # Set the parameters
        self.cluster = self.get_param("cluster")
        self.service = self.get_param("service")
        self.view = self.get_param("view")

        # Initialize the return values
        self.services = []

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        api_instance = ServicesResourceApi(self.api_client)

        if self.view == "healthcheck":
            self.view = "full_with_health_check_explanation"
        elif self.view == "redacted":
            self.view = "export_redacted"

        if self.service:
            try:
                self.services.append(
                    parse_service_result(
                        api_instance.read_service(
                            cluster_name=self.cluster,
                            service_name=self.service,
                            view=self.view,
                        )
                    )
                )
            except ApiException as e:
                if e.status != 404:
                    raise e
        else:
            self.services = [
                parse_service_result(s)
                for s in api_instance.read_services(
                    cluster_name=self.cluster, view=self.view
                ).items
            ]


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            service=dict(aliases=["service_name", "name"]),
            view=dict(
                default="summary",
                choices=["summary", "full", "healthcheck", "export", "redacted"],
            ),
        ),
        supports_check_mode=True,
    )

    result = ClusterServiceInfo(module)

    output = dict(
        changed=False,
        services=result.services,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
