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
short_description: Manage Cloudera Manager hosts
description:
  - Allows for the management of Cloudera Manager hosts.
  - Functionality includes creation and deletion of hosts; host cluster assignment, host template, role config group assignment, and host and role instance configuration.
author:
  - "Ronald Suplina (@rsuplina)"
  - "Webster Mudge (@wmudge)"
options:
  name:
    description:
      - The name of the host.
      - One of O(name) or O(host_id) is required.
    type: str
    aliases:
      - cluster_hostname
  cluster:
    description:
      - The name of the associated (attached) cluster.
      - To remove from a cluster, omit and set I(purge=True).
    type: str
    aliases:
      - cluster_name
  host_id:
    description:
      - The unique identifier of the host. Read-only.
      - One of O(name) or O(host_id) is required.
    type: str
    aliases:
  ip_address:
    description:
      - The IP address of the host.
    type: str
    aliases:
        - host_ip
  rack_id:
    description:
      - The rack ID for this host.
    type: str
  config:
    description:
      - The host configuration overrides to set.
      - To unset a parameter, use V(None) as the value.
    type: dict
    aliases:
      - params
      - parameters
  host_template:
    description:
      - The host template (and associated role instances) to apply to the host.
    type: str
    aliases:
      - template
  roles:
    description:
      - Role configuration overrides for the host.
    type: list
    elements: dict
    options:
      service:
        description:
          - The service of the role instance on the host.
        type: str
        required: yes
        aliases:
          - service_name
      type:
        description:
          - The role type of the role instance on the host.
        type: str
        required: yes
        aliases:
          - role_type
      config:
        description:
          - The host configuration overrides to set.
          - To unset a parameter, use V(None) as the value.
        type: dict
        aliases:
          - params
          - parameters
  role_config_groups:
    description:
      - Role config groups (and associated role instances) to apply to the host.
    type: list
    elements: dict
    options:
      service:
        description:
          - The service of the role config group (and associated role instance) on the host.
        type: str
        required: yes
        aliases:
          - service_name
      type:
        description:
          - The base role type of the role config group (and associated role instance) on the host.
          - One of O(type) or O(name) is required.
        type: str
        aliases:
          - role_type
      name:
        description:
          - The name of the role config group (and associated role instance) on the host.
          - One of O(type) or O(name) is required.
        type: str
  tags:
    description:
      - A set of tags applied to the host.
      - To unset a tag, use V(None) as its value.
    type: dict
  purge:
    description:
      - Flag for whether the declared role configuration overrides, tags, and associated role instance (via O(host_template) or O(role_config_groups)) should append to existing entries or overwrite, i.e. reset, to only the declared entries.
      - To clear all configuration and assignments, set empty dictionaries, e.g. O(config={}), or omit the parameter, e.g. O(role_config_groups), and set O(purge=True).
    type: bool
    default: False
  skip_redacted:
    description:
      - Flag indicating if the declared role configurations overrides and tags should skipped I(REDACTED) parameters during reconciliation.
      - If set, the module will not attempt to update any existing parameter with a I(REDACTED) value.
      - Otherwise, the parameter value will be overridden.
    type: bool
    default: False
    aliases:
      - redacted
  maintenance:
    description:
      - Flag for whether the host should be in maintenance mode.
    type: bool
    aliases:
      - maintenance_mode
  state:
    description:
      - State of the host.
      - The states V(started), V(stopped), and V(restarted) refer the state of the host's role instances.
    type: str
    default: present
    choices:
      - present
      - absent
      - started
      - stopped
      - restarted
  timeout:
    description:
      - Timeout, in seconds, before failing when joining a cluster.
    type: int
    default: 300
    aliases:
      - polling_timeout
  delay:
    description:
      - Delay (interval), in seconds, between each attempt.
    type: int
    default: 15
    aliases:
      - polling_interval
extends_documentation_fragment:
  - ansible.builtin.action_common_attributes
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - cloudera.cluster.message
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
  - module: cloudera.cluster.host_info
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
host:
  description: Details about the host
  type: dict
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

import time

from cm_client import (
    ApiHost,
    ApiHostList,
    ApiHostRef,
    ApiHostRefList,
    ClustersResourceApi,
    HostsResourceApi,
    HostTemplatesResourceApi,
    RolesResourceApi,
)
from cm_client.rest import ApiException

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    reconcile_config_list_updates,
    ClouderaManagerMutableModule,
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


class Host(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(Host, self).__init__(module)

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
        self.skip_redacted = self.get_param("skip_redacted")
        self.maintenance = self.get_param("maintenance")
        self.state = self.get_param("state")
        self.timeout = self.get_param("timeout")
        self.delay = self.get_param("delay")

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

                    (
                        updated_config,
                        config_before,
                        config_after,
                    ) = reconcile_config_list_updates(
                        current.config,
                        self.config,
                        self.purge,
                        self.skip_redacted,
                    )

                    if config_before or config_after:
                        self.changed = True

                        if self.module._diff:
                            self.diff["before"].update(config=config_before)
                            self.diff["after"].update(config=config_after)

                        if not self.module.check_mode:
                            host_api.update_host_config(
                                host_id=current.host_id,
                                message=self.message,
                                body=updated_config,
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
                                msg=f"Cluster not found: {self.cluster}."
                            )

                    # Handle new cluster membership
                    if current.cluster_ref is None:
                        self.changed = True

                        if self.module._diff:
                            self.diff["before"].update(cluster="")
                            self.diff["after"].update(cluster=cluster.name)

                        if not self.module.check_mode:
                            # Add the host to the cluster
                            end_time = time.time() + self.timeout

                            while end_time > time.time():
                                try:
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
                                    break
                                except ApiException as ae:
                                    if ae.status == 400:
                                        self.module.log(
                                            f"[RETRY] Attempting to add host, {current.hostname}, to cluster, {cluster.name}"
                                        )
                                        time.sleep(self.delay)
                                        continue
                                    else:
                                        raise ae

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

                try:
                    (before_ht, after_ht) = reconcile_host_template_assignments(
                        api_client=self.api_client,
                        cluster=cluster,
                        host=current,
                        host_template=ht,
                        purge=self.purge,
                        check_mode=self.module.check_mode,
                    )
                except ApiException as ex:
                    self.module.fail_json(
                        msg=f"Error whil reconciling host template assignments: {to_native(ex)}"
                    )

                if before_ht or after_ht:
                    self.changed = True
                    if self.module._diff:
                        self.diff["before"].update(roles=before_ht)
                        self.diff["after"].update(roles=after_ht)

            # Handle role config group assignment (argspec enforces inclusion of cluster)
            if self.role_config_groups:
                try:
                    (before_rcg, after_rcg) = reconcile_host_role_config_groups(
                        api_client=self.api_client,
                        cluster=cluster,
                        host=current,
                        role_config_groups=self.role_config_groups,
                        purge=self.purge,
                        skip_redacted=self.skip_redacted,
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
            if self.roles:
                try:
                    (before_role, after_role) = reconcile_host_role_configs(
                        api_client=self.api_client,
                        host=current,
                        role_configs=self.roles,
                        purge=self.purge,
                        check_mode=self.module.check_mode,
                        skip_redacted=self.skip_redacted,
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
            skip_redacted=dict(type="bool", default=False, aliases=["redacted"]),
            maintenance=dict(type="bool", aliases=["maintenance_mode"]),
            state=dict(
                default="present",
                choices=[
                    "present",
                    "absent",
                    "started",
                    "stopped",
                    "restarted",
                ],
            ),
            timeout=dict(type="int", default=300, aliases=["polling_timeout"]),
            delay=dict(type="int", default=15, aliases=["polling_interval"]),
        ),
        required_one_of=[
            ("name", "host_id"),
        ],
        # mutually_exclusive=[
        #     ["host_template", "role_config_groups"],
        # ],
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

    result = Host(module)

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
