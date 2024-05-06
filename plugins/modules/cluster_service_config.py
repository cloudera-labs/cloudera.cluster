# Copyright 2023 Cloudera, Inc. All Rights Reserved.
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

import json

from ansible.module_utils.common.dict_transformations import recursive_diff

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerMutableModule,
)

from cm_client import (
    ApiConfig,
    ApiServiceConfig,
    ClustersResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: cluster_service_config
short_description: Manage a service configuration in cluster 
description:
  - Manage a service configuration (service-wide) in a cluster.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
options:
  parameters:
    description:
      - The service-wide configuration to set.
      - To unset a parameter, use C(None) as the value.
    type: dict
    required: yes
    aliases:
      - params
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - cloudera.cluster.cluster_mutable
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
"""

EXAMPLES = r"""
---
- name: Update several service-wide parameters
  cloudera.cluster.cluster_service_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-service
    parameters:
      a_configuration: "schema://host:port"
      another_configuration: 234

- name: Reset or remove a service-wide parameter
  cloudera.cluster.cm_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-service
    parameters:
      more_configuration: None
"""

RETURN = r"""
---
service:
  description: Details about the service.
  type: dict
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
        cluster_name:
          description: The name of the cluster, which uniquely identifies it in a Cloudera Manager installation.
          type: str
          returned: always
        display_name:
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
      description: The dictionary of tags for the service.
      type: dict
      returned: when supported
    service_version:
      description: Version of the service.
      type: str
      returned: when supported
"""


class ClusterServiceConfig(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClusterServiceConfig, self).__init__(module)

        # Set the parameters
        self.cluster = self.get_param("cluster")
        self.service = self.get_param("service")
        self.params = self.get_param("parameters")

        # Initialize the return value
        self.changed = False
        self.diff = {}
        self.config = []

        # Execute the logic
        self.process()

    @ClouderaManagerMutableModule.handle_process
    def process(self):
        try:
            ClustersResourceApi(self.api_client).read_cluster(self.cluster)
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg="Cluster does not exist: " + self.cluster)
            else:
                raise ex

        api_instance = ServicesResourceApi(self.api_client)

        try:
            existing = api_instance.read_service_config(
                self.cluster, self.service, view="full"
            )
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg=json.loads(ex.body)["message"])
            else:
                raise ex

        current = {r.name: r.value for r in existing.items}
        incoming = {k: str(v) if v is not None else v for k, v in self.params.items()}

        (_, add) = recursive_diff(current, incoming)

        if add:
            self.changed = True

            if self.module._diff:
                self.diff = dict(before={k: current[k] for k in add.keys()}, after=add)

            if not self.module.check_mode:
                body = ApiServiceConfig(
                    items=[ApiConfig(name=k, value=v) for k, v in add.items()]
                )

                self.config = [
                    p.to_dict()
                    for p in api_instance.update_service_config(
                        self.cluster, self.service, message=self.message, body=body
                    ).items
                ]
        else:
            # Return 'summary'
            self.config = [
                p.to_dict()
                for p in api_instance.read_service_config(self.cluster, self.service).items
            ]


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            service=dict(required=True, aliases=["service_name", "name"]),
            parameters=dict(type="dict", required=True, aliases=["params"]),
        ),
        supports_check_mode=True,
    )

    result = ClusterServiceConfig(module)

    output = dict(
        changed=result.changed,
        config=result.config,
    )

    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
