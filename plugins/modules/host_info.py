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

from cm_client import HostsResourceApi
from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: host_info
short_description: Gather information about hosts within Cloudera Manager
description:
  - Gather information about the Cloudera Manager host instance.
author:
  - "Ronald Suplina (@rsuplina)"
requirements:
  - cm_client
options:
  cluster_hostname:
    description:
      - The name of the host.
    type: str
    required: no
  host_id:
    description:
      - The ID of the host.
    type: str
    required: no
"""

EXAMPLES = r"""
---
- name: Get information about the host with hostname
  cloudera.cluster.host_info:
    host: "example.cloudera.host"
    username: "will_jordan"
    password: "S&peR4Ec*re"
    cluster_hostname: "Ecs_node_01"

- name: Get information about the host with host id
  cloudera.cluster.host_info:
    host: "example.cloudera.host"
    username: "will_jordan"
    password: "S&peR4Ec*re"
    cluster_hostname: "Ecs_node_01"

- name: Get information about all the hosts registered by Cloudera Manager
  cloudera.cluster.host_info:
    host: "example.cloudera.host"
    username: "will_jordan"
    password: "S&peR4Ec*re"
"""

RETURN = r"""
---
cloudera_manager:
    description: Details about Cloudera Manager Host
    type: list
    elements: dict
    contains:
        hostname:
            description: The hostname. This field is not mutable after the initial creation.
            type: str
            returned: optional
        host_id:
            description: A unique host identifier. This is not the same as the hostname (FQDN). It is a distinct value that remains the same even if the hostname changes.
            type: str
            returned: optional
        host_url:
            description: A URL into the Cloudera Manager web UI for this specific host.
            type: str
            returned: optional
        clusterRef:
            description: A reference to the enclosing cluster.
            type: str
            returned: optional
        commissionState:
            description: Represents the Commission state of an entity.
            type: str
            returned: optional
        distribution:
            description: OS distribution details.
            type: dict
            returned: optional
        entity_status:
            description: The single value used by the Cloudera Manager UI to represent the status of the entity.
            type: str
            returned: optional
        health_checks:
            description: Represents a result from a health test performed by Cloudera Manager for an entity.
            type: list
            returned: optional
        health_summary:
            description: The summary status of health check.
            type: str
            returned: optional
        ip_address:
            description: The host IP address. This field is not mutable after the initial creation.
            type: str
            returned: optional
        last_heartbeat:
            description: Time when the host agent sent the last heartbeat.
            type: str
            returned: optional
        maintenance_mode:
            description: Maintance mode of Cloudera Manager Service.
            type: bool
            returned: optional
        maintenance_owners:
            description: List of Maintance owners for Cloudera Manager Service.
            type: list
            returned: optional
        num_cores:
            description: The number of logical CPU cores on this host.
            type: number
            returned: optional
        numPhysicalCores:
            description: The number of physical CPU cores on this host.
            type: number
            returned: optional
        rack_id:
            description: The rack ID for this host.
            type: str
            returned: optional
        role_refs:
            description: The list of roles assigned to this host.
            type: list
            returned: optional
        tags:
            description: Tags associated with the host.
            type: list
            returned: optional
        total_phys_mem_bytes:
            description: he amount of physical RAM on this host, in bytes.
            type: str
            returned: optional
"""


class ClouderaHostInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaHostInfo, self).__init__(module)

        # Initialize the return values
        self.cluster_hostname = self.get_param("cluster_hostname")
        self.host_id = self.get_param("host_id")
        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):

        host_api_instance = HostsResourceApi(self.api_client)
        self.host_output = {}
        self.changed = False
        if self.cluster_hostname or self.host_id:
            try:
                if self.cluster_hostname:
                    self.host_output = host_api_instance.read_host(
                        host_id=self.cluster_hostname
                    ).to_dict()
                else:
                    self.host_output = host_api_instance.read_host(
                        host_id=self.host_id
                    ).to_dict()
            except ApiException as ex:
                if ex.status != 404:
                    raise ex
        else:
            self.host_output = host_api_instance.read_hosts().to_dict()


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            cluster_hostname=dict(required=False, type="str"),
            host_id=dict(required=False, type="str"),
        ),
        supports_check_mode=True,
    )

    result = ClouderaHostInfo(module)

    changed = result.changed

    output = dict(
        changed=changed,
        cloudera_manager=result.host_output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
