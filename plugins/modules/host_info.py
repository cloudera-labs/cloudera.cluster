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
module: host_info
short_description: Gather information about Cloudera Manager hosts
description:
  - Gather information about the Cloudera Manager host instances.
author:
  - "Ronald Suplina (@rsuplina)"
  - "Webster Mudge (@wmudge)"
options:
  cluster:
    description:
      - The name of the associated (attached) cluster of the hosts.
    type: str
    required: no
    aliases:
      - cluster_name
  name:
    description:
      - The hostname of the host.
    type: str
    required: no
    aliases:
      - cluster_hostname
  host_id:
    description:
      - The unique identifier of the host.
    type: str
    required: no
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - ansible.builtin.action_common_attributes
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
  - module: cloudera.cluster.host
"""

EXAMPLES = r"""
- name: Get information about the host via hostname
  cloudera.cluster.host_info:
    host: "example.cloudera.host"
    username: "will_jordan"
    password: "S&peR4Ec*re"
    name: "ecs_node_01.cldr.internal"

- name: Get information about the host via host id
  cloudera.cluster.host_info:
    host: "example.cloudera.host"
    username: "will_jordan"
    password: "S&peR4Ec*re"
    host_id: "1a12c6a0-9277-4824-aaa9-38e24a6f5efe"

- name: Get information about all the hosts registered with Cloudera Manager
  cloudera.cluster.host_info:
    host: "example.cloudera.host"
    username: "will_jordan"
    password: "S&peR4Ec*re"

- name: Get information about all the hosts attached to a cluster
  cloudera.cluster.host_info:
    host: "example.cloudera.host"
    username: "will_jordan"
    password: "S&peR4Ec*re"
    cluster: "ExampleCluster"
"""

RETURN = r"""
hosts:
  description: Details about Cloudera Manager hosts.
  type: list
  elements: dict
  contains:
    host_id:
      description:
        - The unique ID of the host.
        - This is not the same as the hostname (FQDN); I(host_id) is a distinct value that remains static across hostname changes.
      type: str
      returned: always
    hostname:
      description: The hostname of the host.
      type: str
      returned: when supported
    ip_address:
      description: The IP address of the host.
      type: str
      returned: always
    rack_id:
      description: The rack ID for this host.
      type: str
      returned: when supported
    last_heartbeat:
      description: Time when the host agent sent the last heartbeat.
      type: str
      returned: when supported
    health_summary:
      description: The high-level health status of the host.
      type: str
      returned: always
      sample:
        - DISABLED
        - HISTORY_NOT_AVAILABLE
        - NOT_AVAILABLE
        - GOOD
        - CONCERNING
        - BAD
    health_checks:
      description: Lists all available health checks for the host.
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
            - A suppressed health check is not considered when computing the host's overall health.
          type: bool
          returned: when supported
    maintenance_mode:
      description: Whether the host is in maintenance mode.
      type: bool
      returned: when supported
    commission_state:
      description: Commission state of the host.
      type: str
      returned: always
    maintenance_owners:
      description: The list of objects that trigger this host to be in maintenance mode.
      type: list
      elements: str
      returned: when supported
      sample:
        - CLUSTER
        - SERVICE
        - ROLE
        - HOST
        - CONTROL_PLANE
    num_cores:
      description: The number of logical CPU cores on this host.
      type: number
      returned: when supported
    numPhysicalCores:
      description: The number of physical CPU cores on this host.
      type: number
      returned: when supported
    total_phys_mem_bytes:
      description: he amount of physical RAM on this host, in bytes.
      type: str
      returned: when supported
    config:
      description: Set of host configurations.
      type: dict
      returned: when supported
    distribution:
      description: OS distribution details.
      type: dict
      returned: when supported
    tags:
      description: The dictionary of tags for the host.
      type: dict
      returned: when supported
    cluster_name:
      description: The associated cluster for the host.
      type: str
      returned: when supported
    roles:
      description: The list of role instances, i.e. role identifiers, assigned to this host.
      type: list
      elements: str
      returned: when supported
"""

from cm_client import (
    ApiHost,
    ClustersResourceApi,
    HostsResourceApi,
)
from cm_client.rest import ApiException


from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.host_utils import (
    parse_host_result,
)


class HostInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(HostInfo, self).__init__(module)

        # Set the parameters
        self.cluster = self.get_param("cluster")
        self.name = self.get_param("name")
        self.host_id = self.get_param("host_id")

        # Initialize the return values
        self.output = []

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):

        host_api = HostsResourceApi(self.api_client)
        cluster_api = ClustersResourceApi(self.api_client)

        hosts = list[ApiHost]()

        if self.host_id:
            try:
                hosts.append(host_api.read_host(host_id=self.host_id))
            except ApiException as ex:
                if ex.status != 404:
                    raise ex
        elif self.name:
            host = next(
                (h for h in host_api.read_hosts().items if h.hostname == self.name),
                None,
            )
            if host is not None:
                hosts.append(host)
        elif self.cluster:
            try:
                ClustersResourceApi(self.api_client).read_cluster(self.cluster)
            except ApiException as ex:
                if ex.status == 404:
                    self.module.fail_json(msg="Cluster does not exist: " + self.cluster)
                else:
                    raise ex

            hosts = cluster_api.list_hosts(
                cluster_name=self.cluster,
            ).items
        else:
            hosts = host_api.read_hosts().items

        for host in hosts:
            host.config = host_api.read_host_config(host.host_id)
            self.output.append(parse_host_result(host))


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            cluster=dict(aliases=["cluster_name"]),
            name=dict(aliases=["cluster_hostname"]),
            host_id=dict(),
        ),
        supports_check_mode=True,
    )

    result = HostInfo(module)

    output = dict(
        changed=False,
        hosts=result.output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
