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
module: role_info
short_description: Retrieve information about the service roles of cluster
description:
  - Gather information about one or all service roles of a CDP cluster.
author:
  - "Webster Mudge (@wmudge)"
version_added: "4.4.0"
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
requirements:
  - cm_client
seealso:
  - module: cloudera.cluster.role
"""

EXAMPLES = r"""
- name: Gather details of the roles for the 'yarn' service
  cloudera.cluster.role_info:
    host: "example.cloudera.host"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: yarn

- name: Gather the details with additional healthcheck information for the roles in the 'ecs' service
  cloudera.cluster.role_info:
    host: "example.cloudera.host"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: ecs
    view: healthcheck

- name: Gather details of the 'NODEMANAGER' roles for the 'yarn' service
  cloudera.cluster.role_info:
    host: "example.cloudera.host"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: yarn
    type: NODEMANAGER

- name: Gather details of the roles for the 'yarn' service on a particular cluster host
  cloudera.cluster.role_info:
    host: "example.cloudera.host"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: yarn
    cluster_hostname: "worker09.example.cloudera.internal"
"""

RETURN = r"""
roles:
  description: Details about the roles of cluster service.
  type: list
  elements: dict
  returned: always
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
    service_name:
      description: The name of the cluster service, which uniquely identifies it in a cluster.
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

import json

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    parse_role_result,
    read_role,
    read_roles,
)

from cm_client import ClustersResourceApi, ServicesResourceApi
from cm_client.rest import ApiException


class RoleInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(RoleInfo, self).__init__(module)

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
                self.cluster,
                self.service,
            )
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg=json.loads(ex.body)["message"])
            else:
                raise ex

        if self.view == "healthcheck":
            self.view = "full_with_health_check_explanation"
        elif self.view == "redacted":
            self.view = "export_redacted"

        if self.role:
            try:
                self.roles.append(
                    parse_role_result(
                        read_role(
                            api_client=self.api_client,
                            cluster_name=self.cluster,
                            service_name=self.service,
                            role_name=self.role,
                            view=self.view,
                        ),
                    ),
                )
            except ApiException as e:
                if e.status != 404:
                    raise e
        else:
            self.roles = [
                parse_role_result(s)
                for s in read_roles(
                    api_client=self.api_client,
                    cluster_name=self.cluster,
                    service_name=self.service,
                    view=self.view,
                    type=self.type,
                    hostname=self.cluster_hostname,
                    host_id=self.cluster_host_id,
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

    result = RoleInfo(module)

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
