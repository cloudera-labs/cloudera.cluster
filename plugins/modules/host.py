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
    ApiHostRef,
    ApiHostRefList,
    ApiRoleConfigGroup,
    ClustersResourceApi,
    HostsResourceApi,
    HostTemplatesResourceApi,
    RoleConfigGroupsResourceApi,
    RolesResourceApi,
)
from cm_client.rest import ApiException

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerMutableModule,
    ConfigListUpdates,
    TagUpdates,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.host_utils import (
    create_host_model,
    detach_host,
    get_host,
    get_host_roles,
    parse_host_result,
    reconcile_host_role_configs,
    reconcile_host_role_config_groups,
    reconcile_host_template_assignments,
    toggle_host_maintenance,
    toggle_host_role_states,
    HostMaintenanceStateException,
    HostException,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    parse_role_result,
)


class ClusterHost(ClouderaManagerMutableModule):
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

    @ClouderaManagerMutableModule.handle_process
    def process(self):

        cluster_api = ClustersResourceApi(self.api_client)
        host_api = HostsResourceApi(self.api_client)
        host_template_api = HostTemplatesResourceApi(self.api_client)
        rcg_api = RoleConfigGroupsResourceApi(self.api_client)
        role_api = RolesResourceApi(self.api_client)

        current = None

        try:
            current = get_host(
                api_client=self.api_client,
                hostname=self.name,
                host_id=self.host_id,
                view="full",
            )
        except ApiException as ex:
            if ex.status != 404:
                raise ex

        # If removing
        if self.state == "absent":
            if current:
                self.changed = True

                if self.module._diff:
                    self.diff.update(before=parse_host_result(current), after=dict())

                if not self.module.check_mode:
                    host_api.delete_host(host_id=current["host_id"])

        # Else if a known run state
        elif self.state in [
            "present",
            "started",
            "stopped",
            "restarted",
        ]:
            # If the host does not yet exist, so create and provision the core configuration
            if not current:
                self.changed = True

                if self.ip_address is None:
                    self.module.fail_json(msg="missing required arguments: ip_address")

                # Create and provision the host
                host = create_host_model(
                    api_client=self.api_client,
                    hostname=self.name,
                    ip_address=self.ip_address,
                    rack_id=self.rack_id,
                    config=self.config,
                    tags=self.tags,
                )

                if self.module._diff:
                    self.diff.update(before=dict(), after=parse_host_result(host))

                if not self.module.check_mode:
                    current = host_api.create_hosts(
                        body=ApiHostList(items=[host])
                    ).items[0]

                    if not current:
                        self.module.fail_json(
                            msg="Unable to create new host",
                            host=to_native(host.to_dict()),
                        )

                # Set maintenence mode
                self.handle_maintenance(current)

            # Else the host exists, so update the core configuration
            else:
                # Handle maintenence mode
                self.handle_maintenance(current)

                # Handle IP address configuration
                if self.ip_address and self.ip_address != current.ip_address:
                    self.module.fail_json(
                        msg="Invalid host configuration. To update the host IP address, please remove and then add the host."
                    )

                # Handle rack ID
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

                # Handle host configs
                if self.config or self.purge:
                    if self.config is None:
                        self.config = dict()

                    config_updates = ConfigListUpdates(
                        current.config, self.config, self.purge
                    )

                    if config_updates.changed:
                        self.changed = True

                        if self.module._diff:
                            self.diff["before"].update(
                                config=config_updates.diff["before"]
                            )
                            self.diff["after"].update(
                                config=config_updates.diff["after"]
                            )

                        if not self.module.check_mode:
                            host_api.update_host_config(
                                host_id=current.host_id,
                                message=self.message,
                                body=config_updates.config,
                            )

                # Handle tags
                if self.tags or self.purge:
                    if self.tags is None:
                        self.tags = dict()

                    tag_updates = TagUpdates(current.tags, self.tags, self.purge)

                    if tag_updates.changed:
                        self.changed = True

                        if self.module._diff:
                            self.diff["before"].update(tags=tag_updates.diff["before"])
                            self.diff["after"].update(tags=tag_updates.diff["after"])

                        if not self.module.check_mode:
                            if tag_updates.deletions:
                                host_api.delete_tags(
                                    hostname=current.hostname,
                                    body=tag_updates.deletions,
                                )

                            if tag_updates.additions:
                                host_api.add_tags(
                                    hostname=current.hostname,
                                    body=tag_updates.additions,
                                )

            # Handle attaching and detaching from clusters
            if self.cluster or self.purge:

                # If detaching from a cluster, address the role decommissioning
                if self.cluster is None and self.purge:

                    # Only remove the roles with a cluster reference
                    if current.cluster_ref is not None:
                        self.changed = True

                        current_roles = get_host_roles(self.api_client, host=current)

                        if self.module._diff:
                            self.diff["before"].update(
                                cluster=current.cluster_ref.cluster_name, roles=[]
                            )
                            self.diff["after"].update(cluster="", roles=[])

                        for role in current_roles:
                            if role.service_ref.cluster_name is not None:
                                if self.module._diff:
                                    self.diff["before"]["roles"].append(
                                        parse_role_result(role)
                                    )

                                if not self.module.check_mode:
                                    role_api.delete_role(
                                        cluster_name=role.service_ref.cluster_name,
                                        service_name=role.service_ref.service_name,
                                        role_name=role.name,
                                    )

                        if not self.module.check_mode:
                            cluster_api.remove_host(
                                cluster_name=current.cluster_ref.cluster_name,
                                host_id=current.host_id,
                            )
                # Else if cluster is defined
                elif self.cluster:
                    try:
                        cluster = cluster_api.read_cluster(cluster_name=self.cluster)
                    except ApiException as ex:
                        if ex.status == 404:
                            self.module.fail_json(
                                msg=f"Cluster does not exist:  {self.cluster}"
                            )

                    # Handle new cluster membership
                    if current.cluster_ref is None:
                        self.changed = True

                        if self.module._diff:
                            self.diff["before"].update(cluster="")
                            self.diff["after"].update(cluster=cluster.name)

                        if not self.module.check_mode:
                            cluster_api.add_hosts(
                                cluster_name=cluster.name,
                                body=ApiHostRefList(
                                    items=[
                                        ApiHostRef(
                                            host_id=current.host_id,
                                            hostname=current.hostname,
                                        )
                                    ]
                                ),
                            )

                    # Handle cluster migration
                    elif current.cluster_ref.cluster_name != cluster.name:
                        self.changed = True

                        # Detach from cluster
                        (before_detach, after_detach) = detach_host(
                            api_client=self.api_client,
                            host=current,
                            purge=self.purge,
                            check_mode=self.module.check_mode,
                        )

                        # Attach to new cluster
                        if not self.module.check_mode:
                            cluster_api.add_hosts(
                                cluster_name=cluster.name,
                                body=ApiHostRefList(
                                    items=[
                                        ApiHostRef(
                                            host_id=current.host_id,
                                            hostname=current.hostname,
                                        )
                                    ]
                                ),
                            )

                        if self.module._diff:
                            self.diff["before"].update(
                                cluster=current.cluster_ref.cluster_name,
                                roles=before_detach,
                            )
                            self.diff["after"].update(
                                cluster=cluster.name,
                                roles=after_detach,
                            )

            # Handle host template assignments (argspec enforces inclusion of cluster)
            if self.host_template:
                try:
                    ht = host_template_api.read_host_template(
                        cluster_name=cluster.name,
                        host_template_name=self.host_template,
                    )
                except ApiException as ex:
                    if ex.status == 404:
                        self.module.fail_json(
                            msg=f"Host template, '{self.host_template}', does not exist on cluster, '{cluster.name}'"
                        )

                (before_ht, after_ht) = reconcile_host_template_assignments(
                    api_client=self.api_client,
                    cluster=cluster,
                    host=current,
                    host_template=ht,
                    purge=self.purge,
                    check_mode=self.module.check_mode,
                )

                if before_ht or after_ht:
                    self.changed = True
                    if self.module._diff:
                        self.diff["before"].update(roles=before_ht)
                        self.diff["after"].update(roles=after_ht)

            # Handle role config group assignment (argspec enforces inclusion of cluster)
            # if self.role_config_groups or (not self.host_template and self.purge):
            if self.role_config_groups:
                # if self.role_config_groups is None:
                #     self.role_config_groups = list()

                try:
                    (before_rcg, after_rcg) = reconcile_host_role_config_groups(
                        api_client=self.api_client,
                        cluster=cluster,
                        host=current,
                        role_config_groups=self.role_config_groups,
                        purge=self.purge,
                        check_mode=self.module.check_mode,
                    )
                except HostException as he:
                    self.module.fail_json(msg=to_native(he))

                if before_rcg or after_rcg:
                    self.changed = True
                    if self.module._diff:
                        self.diff["before"].update(role_config_groups=before_rcg)
                        self.diff["after"].update(role_config_groups=after_rcg)

            # Handle role override assignments (argspec enforces inclusion of cluster)
            # if self.roles or self.purge:
            if self.roles:
                # if self.roles is None:
                #     self.roles = list()

                try:
                    (before_role, after_role) = reconcile_host_role_configs(
                        api_client=self.api_client,
                        host=current,
                        role_configs=self.roles,
                        purge=self.purge,
                        check_mode=self.module.check_mode,
                        message=self.message,
                    )
                except HostException as he:
                    self.module.fail_json(msg=to_native(he))

                if before_role or after_role:
                    self.changed = True
                    if self.module._diff:
                        self.diff["before"].update(roles=before_role)
                        self.diff["after"].update(roles=after_role)

            # Handle host role states
            # TODO Examine to make sure they exit if no cluster or roles to exec upon
            if self.state in ["started", "stopped", "restarted"]:
                (before_state, after_state) = toggle_host_role_states(
                    api_client=self.api_client,
                    host=current,
                    state=self.state,
                    check_mode=self.module.check_mode,
                )

                if before_state or after_state:
                    self.changed = True
                    if self.module._diff:
                        self.diff["before"].update(roles=before_state)
                        self.diff["after"].update(roles=after_state)

            # Refresh if state has changed
            if self.changed:
                self.output = parse_host_result(
                    get_host(
                        api_client=self.api_client,
                        host_id=current.host_id,
                        view="full",
                    )
                )
            else:
                self.output = parse_host_result(current)

        else:
            self.module.fail_json(msg="Unknown host state: " + self.state)

    def handle_maintenance(self, host: ApiHost) -> None:
        if self.maintenance is not None:
            try:
                state_changed = toggle_host_maintenance(
                    api_client=self.api_client,
                    host=host,
                    maintenance=self.maintenance,
                    check_mode=self.module.check_mode,
                )
            except HostMaintenanceStateException as ex:
                self.module.fail_json(msg=to_native(ex))

            if state_changed:
                self.changed = True
                if self.module._diff:
                    self.diff["before"].update(maintenance_mode=host.maintenance_mode)
                    self.diff["after"].update(maintenance_mode=self.maintenance)


def main():
    module = ClouderaManagerMutableModule.ansible_module(
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
                choices=[
                    "present",
                    "absent",
                    "attached",
                    "detached",
                    "started",
                    "stopped",
                    "restarted",
                ],
            ),
        ),
        required_one_of=[
            ("name", "host_id"),
        ],
        mutually_exclusive=[
            ["host_template", "role_config_groups"],
        ],
        required_if=[
            ("state", "attached", ("cluster",), False),
            ("state", "started", ("cluster",), False),
            ("state", "stopped", ("cluster",), False),
            ("state", "restarted", ("cluster",), False),
        ],
        required_by={
            "host_template": "cluster",
            "role_config_groups": "cluster",
            "roles": "cluster",
        },
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
