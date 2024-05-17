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
from cm_client import ApiHost, ApiHostList
from cm_client import ClustersResourceApi
from cm_client import HostsResourceApi
from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: host
short_description: Manage hosts within Cloudera Manager
description:
  - Allows for the management of hosts within the Cloudera Manager.
  - It provides functionalities to create, delete, attach, or detach host instance from a cluster.
author:
  - "Ronald Suplina (@rsuplina)"
requirements:
  - cm_client
options:
  cluster_hostname:
    description:
      - The name of the host.
    type: str
    required: yes
  host_ip:
    description:
      - The ip of the host.
    type: str
    required: no
    aliases:
        - cluster_host_ip
  rack_id:
    description:
      - The rack ID for this host.
    type: str
    required: no
  name:
    description:
      - The name of the CM Cluster.
    type: str
    required: no
  state:
    description:
      - State of the host.
    type: str
    default: 'present'
    choices:
      - 'present'
      - 'absent'
      - 'attached'
      - 'detached'
    required: False
extends_documentation_fragment:
  - ansible.builtin.action_common_attributes
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  platform:
    platforms: all
"""

EXAMPLES = r"""
---
- name: Create a host
  cloudera.cluster.host:
    host: "example.cloudera.host"
    username: "will_jordan"
    password: "S&peR4Ec*re"
    rack_id: "/default"
    cluster_hostname: "Ecs_node_01"
    host_ip: "10.9.8.7"
    state: "present"

- name: Attach a host to the Cluster
  cloudera.cluster.host:
    host: "example.cloudera.host"
    username: "will_jordan"
    name: "Base_Edge2AI_Node"
    password: "S&peR4Ec*re"
    cluster_hostname: "Ecs_node_01"
    state: "attached"

- name: Detach a host to the Cluster
  cloudera.cluster.host:
    host: "example.cloudera.host"
    username: "will_jordan"
    name: "Base_Edge2AI_Node"
    password: "S&peR4Ec*re"
    cluster_hostname: "Ecs_node_01"
    state: "detached"

- name: Remove a host
  cloudera.cluster.host:
    host: "example.cloudera.host"
    username: "will_jordan"
    password: "S&peR4Ec*re"
    cluster_hostname: "Ecs_node_01"
    state: "absent"


"""

RETURN = r"""
---
cloudera_manager:
    description: Details about Cloudera Manager Host
    type: dict
    contains:
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
        host_id:
            description: A unique host identifier. This is not the same as the hostname (FQDN). It is a distinct value that remains the same even if the hostname changes.
            type: str
            returned: optional
        host_url:
            description: A URL into the Cloudera Manager web UI for this specific host.
            type: str
            returned: optional
        hostname:
            description: The hostname. This field is not mutable after the initial creation.
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


class ClouderaHost(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaHost, self).__init__(module)

        # Initialize the return values
        self.cluster_hostname = self.get_param("cluster_hostname")
        self.name = self.get_param("name")
        self.host_ip = self.get_param("host_ip")
        self.state = self.get_param("state")
        self.rack_id = self.get_param("rack_id")
        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):

        cluster_api_instance = ClustersResourceApi(self.api_client)
        host_api_instance = HostsResourceApi(self.api_client)
        self.host_output = {}
        self.changed = False
        existing = None

        try:
            existing = host_api_instance.read_host(
                host_id=self.cluster_hostname
            ).to_dict()
        except ApiException as ex:
            if ex.status != 404:
                raise ex

        if self.state == "present":
            if existing:
                host_id = existing["host_id"]
            else:
                host_params = {
                    "hostname": self.cluster_hostname,
                    "ip_address": self.host_ip,
                }
                if self.rack_id:
                    host_params["rack_id"] = self.rack_id
                if not self.module.check_mode:
                    host_list = ApiHostList(items=[ApiHost(**host_params)])
                    create_host = host_api_instance.create_hosts(body=host_list)
                    host_id = create_host.items[0].host_id
                    self.changed = True
            self.host_output = host_api_instance.read_host(host_id=host_id).to_dict()

        elif self.state == "absent":
            if existing:
                if not self.module.check_mode:
                    self.host_output = host_api_instance.delete_host(
                        host_id=existing["host_id"]
                    ).to_dict()
                    self.changed = True

        elif self.state in ["attached", "detached"]:

            try:
                cluster_api_instance.read_cluster(cluster_name=self.name).to_dict()
            except ApiException as ex:
                if ex.status == 404:
                    self.module.fail_json(msg=f"Cluster does not exist:  {self.name}")

            if self.state == "attached":
                if existing:
                    try:
                        if not self.module.check_mode:
                            host_list = ApiHostList(
                                items=[
                                    ApiHost(
                                        hostname=self.cluster_hostname,
                                        host_id=existing["host_id"],
                                    )
                                ]
                            )
                            cluster_api_instance.add_hosts(
                                cluster_name=self.name, body=host_list
                            )
                            host_id = existing["host_id"]
                            self.changed = True
                    except ApiException as ex:
                        if ex.status == 400:
                            pass
                else:
                    host_params = {
                        "hostname": self.cluster_hostname,
                        "ip_address": self.host_ip,
                    }
                    if self.rack_id:
                        host_params["rack_id"] = self.rack_id
                    if not self.module.check_mode:
                        new_host_param = ApiHostList(items=[ApiHost(**host_params)])
                        create_host = host_api_instance.create_hosts(
                            body=new_host_param
                        )
                        host_list = ApiHostList(
                            items=[
                                ApiHost(
                                    hostname=self.cluster_hostname,
                                    host_id=create_host.items[0].host_id,
                                )
                            ]
                        )
                        add_host = cluster_api_instance.add_hosts(
                            cluster_name=self.name, body=host_list
                        )
                        host_id = add_host.items[0].host_id
                        self.changed = True

            elif self.state == "detached":
                if (
                    existing
                    and existing.get("cluster_ref")
                    and existing["cluster_ref"].get("cluster_name")
                ):
                    if not self.module.check_mode:
                        cluster_api_instance.remove_host(
                            cluster_name=existing["cluster_ref"]["cluster_name"],
                            host_id=existing["host_id"],
                        )
                        host_id = existing["host_id"]
                        self.changed = True

            self.host_output = host_api_instance.read_host(
                host_id=self.cluster_hostname
            ).to_dict()


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            cluster_hostname=dict(required=True, type="str"),
            name=dict(required=False, type="str"),
            host_ip=dict(required=False, type="str", aliases=["cluster_host_ip"]),
            rack_id=dict(required=False, type="str"),
            state=dict(
                type="str",
                default="present",
                choices=["present", "absent", "attached", "detached"],
            ),
        ),
        supports_check_mode=True,
        required_if=[
            ("state", "attached", ("name", "host_ip"), False),
            ("state", "detached", ("name",), False),
            ("state", "present", ("host_ip",), False),
        ],
    )

    result = ClouderaHost(module)

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
