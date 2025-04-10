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
module: service
short_description: Manage a service in cluster
description:
  - Manage a service in a cluster.
author:
  - "Webster Mudge (@wmudge)"
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
      - The service.
    type: str
    required: yes
    aliases:
      - service_name
      - name
  display_name:
    description:
      - The Cloudera Manager UI display name for the service.
    type: str
  maintenance:
    description:
      - Flag for whether the service should be in maintenance mode.
    type: bool
    aliases:
      - maintenance_mode
  tags:
    description:
      - A set of tags applied to the service.
      - To unset a tag, use C(None) as its value.
    type: dict
  type:
    description:
      - The service type.
      - Required if I(state) creates a new service.
    type: str
    aliases:
      - service_type
  purge:
    description:
      - Flag for whether the declared service tags should append or overwrite any existing tags.
      - To clear all tags, set I(tags={}), i.e. an empty dictionary, and I(purge=True).
    type: bool
    default: False
  state:
    description:
      - The state of the service.
    type: str
    default: present
    choices:
      - present
      - absent
      - restarted
      - started
      - stopped
extends_documentation_fragment:
  - ansible.builtin.action_common_attributes
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
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
  - module: cloudera.cluster.service_info
"""

EXAMPLES = r"""
- name: Establish a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    type: ECS
    display_name: Example ECS


- name: Stop a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    state: stopped

- name: Force a restart of a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    state: restarted

- name: Set a cluster service into maintenance mode
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    maintenance: yes

- name: Update (append) several tags on a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    tags:
      tag_one: valueOne
      tag_two: valueTwo

- name: Update (purge) the tags on a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    tags:
      tag_three: value_three
    purge: yes

- name: Remove all the tags on a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    tags: {}
    purge: yes

- name: Remove a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    state: absent
"""

RETURN = r"""
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
    cluster_name:
      description: The name of the cluster, which uniquely identifies it in a Cloudera Manager installation.
      type: str
      returned: always
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

from cm_client import (
    ApiEntityTag,
    ApiRoleConfigGroup,
    ApiRoleConfigGroupList,
    ApiRoleNameList,
    ApiService,
    ApiServiceList,
    ClustersResourceApi,
    RoleConfigGroupsResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerMutableModule,
    resolve_tag_updates,
    ConfigListUpdates,
    TagUpdates,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    create_role_config_group,
    get_base_role_config_group,
    provision_role_config_groups,
    update_role_config_group,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    create_role,
    provision_service_role,
    RoleException,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.service_utils import (
    create_service,
    parse_service_result,
    provision_service,
    read_service,
    reconcile_service_role_config_groups,
    reconcile_service_roles,
    toggle_service_maintenance,
    toggle_service_state,
    ServiceMaintenanceStateException,
)


class ClusterService(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClusterService, self).__init__(module)

        # Set the parameters
        self.cluster = self.get_param("cluster")
        self.name = self.get_param("name")
        self.display_name = self.get_param("display_name")
        self.type = self.get_param("type")
        self.maintenance = self.get_param("maintenance")
        self.purge = self.get_param("purge")
        self.config = self.get_param("config")
        self.tags = self.get_param("tags")
        self.roles = self.get_param("roles")
        self.role_config_groups = self.get_param("role_config_groups")
        self.state = self.get_param("state")

        # Initialize the return values
        self.changed = False
        self.diff = dict(before={}, after={})
        self.output = {}

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

        service_api = ServicesResourceApi(self.api_client)
        current = None

        # Try and retrieve the service by name
        try:
            current = read_service(
                api_client=self.api_client,
                cluster_name=self.cluster,
                service_name=self.name,
            )
        except ApiException as ex:
            if ex.status != 404:
                raise ex

        if self.state == "absent":
            if current:
                self.changed = True

                if self.module._diff:
                    self.diff = dict(before=parse_service_result(current), after=dict())

                if not self.module.check_mode:
                    service_api.delete_service(self.cluster, self.name)

        elif self.state in ["present", "restarted", "started", "stopped"]:
            # If it is a new service
            if not current:
                self.changed = True

                if self.type is None:
                    self.module.fail_json(msg=f"missing required arguments: type")

                # Create and provision the service
                service = create_service(
                    api_client=self.api_client,
                    name=self.name,
                    type=self.type,
                    cluster_name=self.cluster,
                    display_name=self.display_name,
                    config=self.config,
                    tags=self.tags,
                    # role_config_groups=self.role_config_groups,
                    # roles=self.roles,
                )

                if self.module._diff:
                    self.diff = dict(
                        before={},
                        after=service.to_dict(),
                    )

                if not self.module.check_mode:
                    current = provision_service(
                        api_client=self.api_client,
                        cluster_name=self.cluster,
                        service=service,
                    )

                    if not current:
                        self.module.fail_json(
                            msg="Unable to create new service",
                            service=to_native(service.to_dict()),
                        )

                # Create and provision the role config groups
                if self.role_config_groups:
                    rcg_list = list()
                    base_rcg = None

                    if self.module._diff:
                        before_rcg, after_rcg = list(), list()

                    for requested_rcg in self.role_config_groups:
                        # Create any custom role config groups
                        if requested_rcg["name"] is not None:
                            custom_rcg = create_role_config_group(
                                api_client=self.api_client,
                                cluster_name=self.cluster,
                                service_name=current.name,
                                name=requested_rcg["name"],
                                role_type=requested_rcg["role_type"],
                                display_name=requested_rcg.get("display_name", None),
                                config=requested_rcg.get("config", None),
                            )

                            rcg_list.append(custom_rcg)

                            if self.module._diff:
                                before_rcg.append(dict())
                                after_rcg.append(custom_rcg.to_dict())

                        # Else record the base role config group for modification
                        else:
                            current_base_rcg = get_base_role_config_group(
                                api_client=self.api_client,
                                cluster_name=self.cluster,
                                service_name=current.name,
                                role_type=requested_rcg["role_type"],
                            )

                            (base_rcg, before, after) = update_role_config_group(
                                role_config_group=current_base_rcg,
                                display_name=requested_rcg.get("display_name", None),
                                config=requested_rcg.get("config", None),
                                purge=self.purge,
                            )

                            if self.module._diff:
                                before_rcg.append(before)
                                after_rcg.append(after)

                    if self.module._diff:
                        self.diff["before"]["role_config_groups"] = before_rcg
                        self.diff["after"]["role_config_groups"] = after_rcg

                    if not self.module.check_mode:
                        provision_role_config_groups(
                            api_client=self.api_client,
                            cluster_name=self.cluster,
                            service_name=current.name,
                            role_config_groups=rcg_list,
                        )

                        if base_rcg is not None:
                            RoleConfigGroupsResourceApi(
                                self.api_client
                            ).update_role_config_group(
                                cluster_name=self.cluster,
                                service_name=current.name,
                                role_config_group_name=base_rcg.name,
                                message=self.message,
                                body=base_rcg,
                            )

                # Create and provision roles
                if self.roles:
                    if self.module._diff:
                        role_entries_before, role_entries_after = list(), list()

                    for requested_role in self.roles:
                        if self.module._diff:
                            role_instances_before, role_instances_after = list(), list()

                        for role_host in requested_role["hostnames"]:
                            try:
                                created_role = create_role(
                                    api_client=self.api_client,
                                    cluster_name=self.cluster,
                                    service_name=current.name,
                                    role_type=requested_role["type"],
                                    hostname=role_host,
                                    config=requested_role.get("config", None),
                                    role_config_group=requested_role.get(
                                        "role_config_group", None
                                    ),
                                    tags=requested_role.get("tags", None),
                                )
                            except RoleException as ex:
                                self.module.fail_json(msg=to_native(ex))

                            if self.module._diff:
                                role_instances_before.append(dict())
                                role_instances_after.append(created_role.to_dict())

                            if not self.module.check_mode:
                                provisioned_role = provision_service_role(
                                    api_client=self.api_client,
                                    cluster_name=self.cluster,
                                    service_name=current.name,
                                    role=created_role,
                                )

                                if not provisioned_role:
                                    self.module.fail_json(
                                        msg=f"Unable to create new role in service '{current.name}'",
                                        role=to_native(provisioned_role.to_dict()),
                                    )

                        if self.module._diff:
                            role_entries_before.append(role_instances_before)
                            role_entries_after.append(role_instances_after)

                # Set the maintenance
                self.handle_maintenance(current)

            # Else the service exists, so address any changes
            else:
                if self.type and self.type.upper() != current.type:
                    self.module.fail_json(
                        msg="Service name already in use for type: " + current.type
                    )

                # Set the maintenance
                self.handle_maintenance(current)

                # Handle service-wide configurations
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
                            service_api.update_service_config(
                                cluster_name=self.cluster,
                                service_name=self.name,
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
                                service_api.delete_tags(
                                    cluster_name=self.cluster,
                                    service_name=self.name,
                                    body=tag_updates.deletions,
                                )

                            if tag_updates.additions:
                                service_api.add_tags(
                                    cluster_name=self.cluster,
                                    service_name=self.name,
                                    body=tag_updates.additions,
                                )

                # Handle service details (currently, only display_name)
                if self.display_name and self.display_name != current.display_name:
                    self.changed = True
                    current.display_name = self.display_name

                    if self.module._diff:
                        self.diff["before"].update(display_name=current.display_name)
                        self.diff["after"].update(display_name=self.display_name)

                    if not self.module.check_mode:
                        service_api.update_service(
                            cluster_name=self.cluster,
                            service_name=self.name,
                            body=current,
                        )

                # Handle role config groups
                if self.role_config_groups or self.purge:
                    if self.role_config_groups is None:
                        self.role_config_groups = list()

                    (before_rcg, after_rcg) = reconcile_service_role_config_groups(
                        api_client=self.api_client,
                        service=current,
                        role_config_groups=self.role_config_groups,
                        purge=self.purge,
                        check_mode=self.module.check_mode,
                    )

                    if before_rcg or after_rcg:
                        self.changed = True
                        if self.module._diff:
                            self.diff["before"].update(role_config_groups=before_rcg)
                            self.diff["after"].update(role_config_groups=after_rcg)

                # Handle roles
                if self.roles or self.purge:
                    if self.roles is None:
                        self.roles = list()

                    (before_role, after_role) = reconcile_service_roles(
                        api_client=self.api_client,
                        service=current,
                        roles=self.roles,
                        purge=self.purge,
                        check_mode=self.module.check_mode,
                        # state=self.state,
                        # maintenance=self.maintenance,
                    )

                    if before_role or after_role:
                        self.changed = True
                        if self.module._diff:
                            self.diff["before"].update(roles=before_role)
                            self.diff["after"].update(roles=after_role)

            # Handle state changes
            state_changed = toggle_service_state(
                api_client=self.api_client,
                service=current,
                state=self.state,
                check_mode=self.module.check_mode,
            )

            if state_changed is not None:
                self.changed = True
                if self.module._diff:
                    self.diff["before"].update(service_state=current.service_state)
                    self.diff["after"].update(service_state=state_changed)

            # If there are changes, get a fresh read
            if self.changed:
                self.output = parse_service_result(
                    read_service(
                        api_client=self.api_client,
                        cluster_name=self.cluster,
                        service_name=self.name,
                    )
                )
            else:
                self.output = parse_service_result(current)
        else:
            self.module.fail_json(msg=f"Invalid state: {self.state}")

    def handle_maintenance(self, service: ApiService) -> None:
        if self.maintenance is not None:
            try:
                state_changed = toggle_service_maintenance(
                    api_client=self.api_client,
                    service=service,
                    maintenance=self.maintenance,
                    check_mode=self.module.check_mode,
                )
            except ServiceMaintenanceStateException as ex:
                self.module.fail_json(msg=to_native(ex))

            if state_changed:
                self.changed = True
                if self.module._diff:
                    self.diff["before"].update(
                        maintenance_mode=service.maintenance_mode
                    )
                    self.diff["after"].update(maintenance_mode=self.maintenance)


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            name=dict(required=True, aliases=["service_name", "service"]),
            display_name=dict(),
            type=dict(aliases=["service_type"]),
            # version=dict(),
            maintenance=dict(type="bool", aliases=["maintenance_mode"]),
            purge=dict(type="bool", default=False),
            config=dict(type="dict", aliases=["service_wide_config"]),
            tags=dict(type="dict"),
            roles=dict(
                type="list",
                elements="dict",
                options=dict(
                    type=dict(required=True, aliases=["role_type"]),
                    hostnames=dict(
                        required=True,
                        type="list",
                        elements="str",
                        aliases=["cluster_hosts", "cluster_hostnames"],
                    ),
                    # maintenance=dict(type="bool", aliases=["maintenance_mode"]),
                    config=dict(type="dict", aliases=["parameters", "params"]),
                    role_config_group=dict(),
                    tags=dict(type="dict"),
                ),
            ),
            role_config_groups=dict(
                type="list",
                elements="dict",
                options=dict(
                    name=dict(aliases=["role_config_group_name", "role_config_group"]),
                    display_name=dict(),
                    role_type=dict(aliases=["type"]),
                    config=dict(type="dict", aliases=["params", "parameters"]),
                ),
                required_one_of=[
                    ["name", "role_type"],
                ],
            ),
            state=dict(
                default="present", choices=["present", "absent", "started", "stopped"]
            ),
        ),
        supports_check_mode=True,
    )

    result = ClusterService(module)

    output = dict(
        changed=result.changed,
        service=result.output,
    )

    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
