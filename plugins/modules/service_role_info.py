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

import json

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
    parse_role_result,
)

from cm_client import ClustersResourceApi, RolesResourceApi, ServicesResourceApi
from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: service_role_info
short_description: Retrieve information about the service roles of cluster
description:
  - Gather information about service roles of a CDP cluster.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
options:
  cluster:
    description:
      - The associated cluster.
    type: str
    required: yes
    aliases:
      - cluster_name
  service:
    description:
      - The associated service.
    type: str
    required: yes
    aliases:
      - service_name
  role:
    description:
      - A role name to examine.
      - If absent, all roles for the I(service) will be returned.
      - Mutually exclusive with I(cluster_hostname), I(cluster_host_id), and I(type).
    type: str
    aliases:
      - role_name
      - name
  cluster_hostname:
    description:
      - A cluster hostname filter for returned roles.
      - Mutually exclusive with I(role) and I(cluster_host_id).
    type: str
    aliases:
      - cluster_host
  cluster_host_id:
    description:
      - A cluster host ID filter for returned roles.
      - Mutually exclusive with I(role) and I(cluster_hostname).
    type: str
  type:
    description:
      - A role type filter for returned roles.
      - Mutually exclusive with I(role).
    type: str
    aliases:
      - role_type
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
- name: Gather details of the roles for the 'yarn' service
  cloudera.cluster.service_role_info:
    host: "example.cloudera.host"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: yarn
  
- name: Gather the details with additional healthcheck information for the roles in the 'ecs' service
  cloudera.cluster.service_role_info:
    host: "example.cloudera.host"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: ecs
    view: healthcheck
    
- name: Gather details of the 'NODEMANAGER' roles for the 'yarn' service
  cloudera.cluster.service_role_info:
    host: "example.cloudera.host"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: yarn
    type: NODEMANAGER
    
- name: Gather details of the roles for the 'yarn' service on a particular cluster host
  cloudera.cluster.service_role_info:
    host: "example.cloudera.host"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: yarn
    cluster_hostname: "worker09.example.cloudera.internal"
"""

RETURN = r"""
---
roles:
  description: Details about the roles of cluster service.
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
    host_ref:
      description: The associated cluster host running the cluster service role.
      type: dict
      returned: always
      contains:
        host_id:
          description: The unique ID of the cluster host.
          type: str
          returned: always
        hostname:
          description: The hostname of the cluster host.
          type: str
          returned: when supported
    service_ref:
      description: The associated service and cluster references.
      type: dict
      returned: always
      contains:
        peer_name:
          description: The name of the Cloudera Manager peer corresponding to the remote Cloudera Manager which manages the cluster service.
          type: str
          returned: when supported
        cluster_name:
          description: The name of the cluster, which uniquely identifies it in a Cloudera Manager installation.
          type: str
          returned: always
        service_name:
          description: The name of the cluster service, which uniquely identifies it in a cluster.
          type: str
          returned: always
        service_display_name:
          description: The display name of the cluster service.
          type: str
          returned: when supported
        service_type:
          description: The type of the cluster service.
          type: str
          returned: when supported
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
    role_config_group_ref:
      description: The associated role configuration group for this cluster service role.
      type: dict
      returned: when supported
      contains:
        role_config_group_name:
          description: The name of the cluster service role config group, which uniquely identifies it in a Cloudera Manager installation.
          type: str
          returned: always
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
"""


class ClusterServiceRoleInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClusterServiceRoleInfo, self).__init__(module)

        # Set the parameters
        self.cluster = self.get_param("cluster")
        self.service = self.get_param("service")
        self.role = self.get_param("role")
        self.type = self.get_param("type")
        self.cluster_hostname = self.get_param("cluster_hostname")
        self.cluster_host_id = self.get_param("cluster_host_id")
        self.view = self.get_param("view")

        # Initialize the return values
        self.roles = []

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

        try:
            ServicesResourceApi(self.api_client).read_service(
                self.cluster, self.service
            )
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg=json.loads(ex.body)["message"])
            else:
                raise ex

        api_instance = RolesResourceApi(self.api_client)

        if self.view == "healthcheck":
            self.view = "full_with_health_check_explanation"
        elif self.view == "redacted":
            self.view = "export_redacted"

        if self.role:
            try:
                self.roles.append(
                    parse_role_result(
                        api_instance.read_role(
                            cluster_name=self.cluster,
                            role_name=self.role,
                            service_name=self.service,
                            view=self.view,
                        )
                    )
                )
            except ApiException as e:
                if e.status != 404:
                    raise e
        elif self.type or self.cluster_hostname or self.cluster_host_id:
            filter = ";".join(
                [
                    f"{f[0]}=={f[1]}"
                    for f in [
                        ("type", self.type),
                        ("hostname", self.cluster_hostname),
                        ("hostId", self.cluster_host_id),
                    ]
                    if f[1] is not None
                ]
            )

            self.roles = [
                parse_role_result(s)
                for s in api_instance.read_roles(
                    cluster_name=self.cluster,
                    service_name=self.service,
                    view=self.view,
                    filter=filter,
                ).items
            ]
        else:
            self.roles = [
                parse_role_result(s)
                for s in api_instance.read_roles(
                    cluster_name=self.cluster, service_name=self.service, view=self.view
                ).items
            ]


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            service=dict(required=True, aliases=["service_name"]),
            role=dict(aliases=["role_name", "name"]),
            cluster_hostname=dict(aliases=["cluster_host"]),
            cluster_host_id=dict(),
            type=dict(aliases=["role_type"]),
            view=dict(
                default="summary",
                choices=["summary", "full", "healthcheck", "export", "redacted"],
            ),
        ),
        mutually_exclusive=[
            ["role", "cluster_hostname"],
            ["role", "cluster_host_id"],
            ["role", "type"],
            ["cluster_hostname", "cluster_host_id"],
        ],
        supports_check_mode=True,
    )

    result = ClusterServiceRoleInfo(module)

    output = dict(
        changed=False,
        roles=result.roles,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
