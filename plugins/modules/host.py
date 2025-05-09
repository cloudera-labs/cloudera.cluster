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

DOCUMENTATION = r"""
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

from cm_client import (
    ApiHost,
    ApiHostList,
    ClustersResourceApi,
    HostsResourceApi,
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.host_utils import (
    create_host_model,
    get_host,
    parse_host_result,
)


class ClusterHost(ClouderaManagerModule):
    def __init__(self, module):
        super(ClusterHost, self).__init__(module)

        # Set the parameters
        self.name = self.get_param("name")
        self.cluster = self.get_param("cluster")
        self.host_id = self.get_param("host_id")
        self.ip_address = self.get_param("ip_address")
        self.rack_id = self.get_param("rack_id")
        self.config = self.get_param("config")
        self.host_template = self.get_param("host_template")
        self.roles = self.get_param("roles")
        self.role_config_groups = self.get_param("role_config_groups")
        self.tags = self.get_param("tags")
        self.purge = self.get_param("purge")
        self.maintenance = self.get_param("maintenance")
        self.state = self.get_param("state")

        # Initialize the return values
        self.output = {}
        self.diff = dict(before=dict(), after=dict())
        self.changed = False

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):

        cluster_api = ClustersResourceApi(self.api_client)
        host_api = HostsResourceApi(self.api_client)

        current = None

        try:
            current = get_host(
                api_client=self.api_client,
                hostname=self.name,
                host_id=self.host_id,
            )
        except ApiException as ex:
            if ex.status != 404:
                raise ex

        if self.state == "absent":
            if current:
                self.changed = True

                if self.module._diff:
                    self.diff.update(before=parse_host_result(current), after=dict())

                if not self.module.check_mode:
                    host_api.delete_host(host_id=current["host_id"])

        elif self.state == "present":
            if current:
                if self.ip_address and self.ip_address != current.ip_address:
                    self.module.fail_json(
                        msg="Invalid host configuration. To update the host IP address, please remove and then add the host."
                    )

                if self.rack_id and self.rack_id != current.rack_id:
                    self.changed = True

                    if self.module._diff:
                        self.diff["before"].update(rack_id=current.rack_id)
                        self.diff["after"].update(rack_id=self.rack_id)

                    current.rack_id = self.rack_id

                    # Currently, update_host() only handles rack_id, so executing here, not further in the logic
                    if not self.module.check_mode:
                        current = host_api.update_host(
                            host_id=current.host_id, body=current
                        )

                # Handle host template assignment
                # TODO Read the RCGs for the HT, index by type, and then compare vs the actual role types
                # on the instance. If any deltas (read: additions), reapply the HT.

                # Handle role config group assignment

                # Handle role override assignment

            else:
                if self.ip_address is None:
                    self.module.fail_json(
                        "Invalid host configuration. IP address is required for new hosts."
                    )

                current = create_host_model(
                    api_client=self.api_client,
                    hostname=self.name,
                    ip_address=self.ip_address,
                    rack_id=self.rack_id,
                    config=self.config,
                    tags=self.tags,
                )

                self.changed = True

                if self.module._diff:
                    self.diff.update(before=dict(), after=parse_host_result(current))

                if not self.module.check_mode:
                    current = host_api.create_hosts(
                        body=ApiHostList(items=[current])
                    ).items[0]

        elif self.state in ["attached", "detached"]:

            try:
                cluster_api.read_cluster(cluster_name=self.name).to_dict()
            except ApiException as ex:
                if ex.status == 404:
                    self.module.fail_json(msg=f"Cluster does not exist:  {self.name}")

            if self.state == "attached":
                if current:
                    try:
                        if not self.module.check_mode:
                            host_list = ApiHostList(
                                items=[
                                    ApiHost(
                                        hostname=self.cluster_hostname,
                                        host_id=current["host_id"],
                                    )
                                ]
                            )
                            cluster_api.add_hosts(
                                cluster_name=self.name, body=host_list
                            )
                            host_id = current["host_id"]
                            self.changed = True
                    except ApiException as ex:
                        if ex.status == 400:
                            pass
                else:
                    host_params = {
                        "hostname": self.cluster_hostname,
                        "ip_address": self.ip_address,
                    }
                    if self.rack_id:
                        host_params["rack_id"] = self.rack_id
                    if not self.module.check_mode:
                        new_host_param = ApiHostList(items=[ApiHost(**host_params)])
                        create_host = host_api.create_hosts(body=new_host_param)
                        host_list = ApiHostList(
                            items=[
                                ApiHost(
                                    hostname=self.cluster_hostname,
                                    host_id=create_host.items[0].host_id,
                                )
                            ]
                        )
                        add_host = cluster_api.add_hosts(
                            cluster_name=self.name, body=host_list
                        )
                        host_id = add_host.items[0].host_id
                        self.changed = True

            elif self.state == "detached":
                if (
                    current
                    and current.get("cluster_ref")
                    and current["cluster_ref"].get("cluster_name")
                ):
                    if not self.module.check_mode:
                        cluster_api.remove_host(
                            cluster_name=current["cluster_ref"]["cluster_name"],
                            host_id=current["host_id"],
                        )
                        host_id = current["host_id"]
                        self.changed = True

        # Refresh if state has changed
        if self.changed:
            self.output = parse_host_result(host_api.read_host(host_id=current.host_id))
        else:
            self.output = parse_host_result(current)


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            name=dict(aliases=["cluster_hostname"]),
            cluster=dict(aliases=["cluster_name"]),
            host_id=dict(),
            ip_address=dict(aliases=["host_ip"]),
            rack_id=dict(),
            config=dict(type="dict", aliases=["parameters", "params"]),
            host_template=dict(aliases=["template"]),
            roles=dict(
                type="list",
                elements="dict",
                options=dict(
                    service=dict(required=True, aliases=["service_name"]),
                    type=dict(required=True, aliases=["role_type"]),
                    config=dict(type=dict, aliases=["parameters", "params"]),
                ),
            ),
            role_config_groups=dict(
                type="list",
                elements="dict",
                options=dict(
                    service=dict(required=True, aliases=["service_name"]),
                    type=dict(aliases=["role_type"]),
                    name=dict(),
                ),
                required_one_of=[
                    ("type", "name"),
                ],
            ),
            tags=dict(type="dict"),
            purge=dict(type="bool", default=False),
            maintenance=dict(type="bool", aliases=["maintenance_mode"]),
            state=dict(
                default="present",
                choices=["present", "absent", "attached", "detached"],
            ),
        ),
        required_one_of=[
            ("name", "host_id"),
        ],
        required_if=[
            ("state", "attached", ("cluster",), False),
            # ("state", "attached", ("name", "ip_address",), False),
            # ("state", "detached", ("name",), False),
            # ("state", "present", ("ip_address",), False), # TODO Move to execution check
        ],
        supports_check_mode=True,
    )

    result = ClusterHost(module)

    output = dict(
        changed=result.changed,
        host=result.output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
