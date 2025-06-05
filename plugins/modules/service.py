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
      - The associated cluster of the service.
    type: str
    required: yes
    aliases:
      - cluster_name
  name:
    description:
      - The service to manage.
      - This is a unique identifier within the cluster.
    type: str
    required: yes
    aliases:
      - service_name
      - service
  display_name:
    description:
      - The Cloudera Manager UI display name for the service.
    type: str
  type:
    description:
      - The service type.
      - Required if O(state) creates a new service.
    type: str
    aliases:
      - service_type
  maintenance:
    description:
      - Flag indicating if the service should be in maintenance mode.
    type: bool
    aliases:
      - maintenance_mode
  purge:
    description:
      - Flag indicating if the declared service-wide configurations, tags, role config groups, and role assignments and configurations should be append-only or fully reconciled.
      - If set, the module will actively remove undeclared entries, e.g. remove roles.
      - To clear all service-wide configurations and tags, set O(tags={}) or O(config={}), i.e. an empty dictionary, and O(purge=True).
    type: bool
    default: False
  skip_redacted:
    description:
      - Flag indicating if the declared service-wide configurations, tags, role config groups, and role assignments and configurations should skipped I(REDACTED) parameters during reconciliation.
      - If set, the module will not attempt to update any existing parameter with a I(REDACTED) value.
      - Otherwise, the parameter value will be overridden.
    type: bool
    default: False
    aliases:
      - redacted
  config:
    description:
      - A set of service-wide configurations for the service.
      - To unset a configuration, use V(None) as its value.
      - If O(purge=True), undeclared configurations will be removed.
    type: dict
  tags:
    description:
      - A set of tags applied to the service.
      - To unset a tag, use V(None) as its value.
      - If O(purge=True), undeclared tags will be removed.
    type: dict
  roles:
    description:
      - List of service roles to provision directly to cluster hosts.
      - If O(purge=True), undeclared roles for the service will be removed from the hosts.
    type: list
    elements: dict
    options:
      type:
        description:
          - The role instance type to provision on the designated cluster hosts.
        type: str
        required: yes
        aliases:
          - role_type
      hostnames:
        description:
          - List of hostnames of the cluster hosts receiving the role type instance.
        type: list
        elements: str
        required: yes
        aliases:
          - cluster_hosts
          - cluster_hostnames
      config:
        description:
          - A set of role override configurations for the role instance on the cluster hosts.
          - To unset a configuration, use V(None) as its value.
          - If O(purge=True), undeclared configurations will be removed.
        type: dict
        aliases:
          - parameters
          - params
      role_config_group:
        description:
          - A named (custom) role config group to assign to the role instance on the cluster hosts.
          - To unset the assignment, use V(None) as the value.
        type: str
      tags:
        description:
          - A set of tags applied to the role type instance on the cluster hosts.
          - To unset a tag, use V(None) as its value.
          - If O(purge=True), undeclared tags will be removed.
        type: dict
  role_config_groups:
    description:
      - List of base and named (custom) role config groups to declare and configure for the service.
      - If O(purge=True), undeclared named (custom) role config groups will be removed and their
        associated role instances reassigned to each role type's base role config group. (Base role
        config groups cannot be removed.)
    type: list
    elements: dict
    options:
      name:
        description:
          - The name of a custom role config group.
        type: str
        aliases:
          - role_config_group_name
          - role_config_group
      display_name:
        description:
          - The Cloudera Manager UI display name for the role config group.
        type: str
      role_type:
        description:
          - The role type of the base or named (custom) role config group.
        type: str
        required: yes
        aliases:
          - type
      config:
        description:
          - A set of role config group configurations.
          - To unset a configuration, use V(None) as its value.
          - If O(purge=True), undeclared configurations will be removed.
        type: dict
        aliases:
          - parameters
          - params
  state:
    description:
      - The state of the service.
      - Setting O(state=restarted) will always result in a V(changed=True) result.
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

- name: Update (append) several service-wide configurations on a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    config:
      param_one: 1
      param_two: Two

- name: Update (purge) the service-wide configurations on a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    config:
      param_one: 1
      param_three: three
    purge: yes

- name: Remove all the service-wide configurations on a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    config: {}
    purge: yes

- name: Provision role instances on cluster hosts for a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    roles:
      - type: SERVER
        hostnames:
          - host1.example
          - host2.example
        config:
          param_one: 1

- name: Provision role config groups (base and named) for a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    role_config_group:
      - name: custom_server_1
        display_name: Custom Server (1)
        role_type: SERVER
        config:
          param_two: Two
      - role_type: SERVER # This is the base role config group for SERVER
        config:
          param_three: three

- name: Provision a cluster service with hosts, role config groups, and role assignments
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    roles:
      - type: SERVER
        hostnames:
          - host1.example
        config:
          param_two: Twelve
        role_config_group: custom_server_1
      - type: SERVER # Will use the base role config group for SERVER
        hostnames:
          - host2.example
    role_config_group:
      - name: custom_server_1
        display_name: Custom Server (1)
        role_type: SERVER
        config:
          param_two: Two
      - role_type: SERVER # This is the base role config group for SERVER
        config:
          param_three: three

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
    config:
      description: Service-wide configuration details about a cluster service.
      type: dict
      returned: when supported
    role_config_groups:
      description: List of base and custom role config groups for the cluster service.
      type: list
      elements: dict
      contains:
        name:
          description:
            - The unique name of this role config group.
          type: str
          returned: always
        role_type:
          description:
            - The type of the roles in this group.
          type: str
          returned: always
        base:
          description:
            - Flag indicating whether this is a base group.
          type: bool
          returned: always
        display_name:
          description:
            - A user-friendly name of the role config group, as would have been shown in the web UI.
          type: str
          returned: when supported
        config:
          description: Set of configurations for the role config group.
          type: dict
          returned: when supported
      returned: when supported
    roles:
      description: List of provisioned role instances on cluster hosts for the cluster service.
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
        host_id:
          description: The unique ID of the cluster host.
          type: str
          returned: always
        hostname:
          description: The hostname of the cluster host.
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
        config:
          description: Set of role configurations for the cluster service role.
          type: dict
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
      returned: when supported
"""

from cm_client import (
    ApiService,
    ClustersResourceApi,
    RoleConfigGroupsResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerMutableModule,
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
    create_service_model,
    parse_service_result,
    provision_service,
    read_service,
    reconcile_service_config,
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
        self.skip_redacted = self.get_param("skip_redacted")
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
                    self.module.fail_json(msg="missing required arguments: type")

                # Create and provision the service
                service = create_service_model(
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
                    custom_rcg_list = list()
                    base_rcg_list = list()

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

                            custom_rcg_list.append(custom_rcg)

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
                                skip_redacted=self.skip_redacted,
                            )

                            base_rcg_list.append(base_rcg)

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
                            role_config_groups=custom_rcg_list,
                        )

                        for base_rcg in base_rcg_list:
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

                    (before_config, after_config) = reconcile_service_config(
                        api_client=self.api_client,
                        service=current,
                        config=self.config,
                        purge=self.purge,
                        check_mode=self.module.check_mode,
                        skip_redacted=self.skip_redacted,
                        message=self.message,
                    )

                    if before_config or after_config:
                        self.changed = True
                        if self.module._diff:
                            self.diff["before"].update(config=before_config)
                            self.diff["after"].update(config=after_config)

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
                        skip_redacted=self.skip_redacted,
                        message=self.message,
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
                        skip_redacted=self.skip_redacted,
                        message=self.message,
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
            skip_redacted=dict(type="bool", default=False, aliases=["redacted"]),
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
                    role_type=dict(required=True, aliases=["type"]),
                    config=dict(type="dict", aliases=["params", "parameters"]),
                ),
            ),
            state=dict(
                default="present",
                choices=["present", "absent", "started", "stopped", "restarted"],
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
