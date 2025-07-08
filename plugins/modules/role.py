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
module: role
short_description: Manage a service role in cluster
description:
  - Manage a service role in a cluster.
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
  name:
    description:
      - The role name, i.e. the auto-generated identifier.
      - Either O(name) or O(type) must be provided.
    type: str
    aliases:
      - role_name
      - role
  type:
    description:
      - A role type for the role.
      - Either O(name) or O(type) must be provided.
      - Required to provision a new role.
    type: str
    aliases:
      - role_type
  cluster_hostname:
    description:
      - The hostname of a cluster instance for the role.
      - Mutually exclusive with I(cluster_host_id).
      - Either O(cluster_host_id) or O(cluster_hostname) must be provided if O(type) is present.
    type: str
    aliases:
      - cluster_host
  cluster_host_id:
    description:
      - The host ID of a cluster instance for the role.
      - Mutually exclusive with I(cluster_hostname).
      - Either O(cluster_host_id) or O(cluster_hostname) must be provided if O(type) is present.
    type: str
  maintenance:
    description:
      - Flag for whether the role should be in maintenance mode.
    type: bool
    aliases:
      - maintenance_mode
  config:
    description:
      - The role configuration overrides to set.
      - To unset a parameter, use V(None) as the value.
    type: dict
    aliases:
      - params
      - parameters
  tags:
    description:
      - A set of tags applied to the role.
      - To unset a tag, use V(None) as its value.
    type: dict
  role_config_group:
    description:
      - The role configuration group name to assign to the role.
      - To assign the I(base) role configuration group, i.e. the default, set O(role_config_group=None).
    type: str
  purge:
    description:
      - Flag for whether the declared role configuration overrides and tags should append or overwrite any existing entries.
      - To clear all configuration overrides or tags, set O(config={}) or O(tags={}), i.e. an empty dictionary, respectively, and set O(purge=True).
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
  state:
    description:
      - The state of the role.
      - Note, if the declared state is invalid for the role type, for example, C(HDFS GATEWAY), the module will return an error.
    type: str
    default: present
    choices:
      - present
      - absent
      - restarted
      - started
      - stopped
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - cloudera.cluster.message
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
  - module: cloudera.cluster.role_info
"""

EXAMPLES = r"""
- name: Provision a service role
  cloudera.cluster.role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    type: GATEWAY
    cluster_hostname: worker-01.cloudera.internal

- name: Set a service role to maintenance mode (using role name)
  cloudera.cluster.role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    name: example-GATEWAY
    maintenance: true

- name: Update (append) tags to a service role
  cloudera.cluster.role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    type: GATEWAY
    cluster_hostname: worker-01.cloudera.internal
    tags:
      tag_one: value_one
      tag_two: value_two

- name: Set (purge) tags to a service role
  cloudera.cluster.role:
    host: example.cloudera.com
    username: "jane_smith"
    cluster: example-cluster
    service: example-hdfs
    type: GATEWAY
    cluster_hostname: worker-01.cloudera.internal
    tags:
      tag_three: value_three
    purge: true

- name: Remove all tags on a service role
  cloudera.cluster.role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    type: GATEWAY
    cluster_hostname: worker-01.cloudera.internal
    tags: {}
    purge: true

- name: Start a service role
  cloudera.cluster.role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    type: GATEWAY
    cluster_hostname: worker-01.cloudera.internal
    state: started

- name: Force a restart to a service role
  cloudera.cluster.role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    type: GATEWAY
    cluster_hostname: worker-01.cloudera.internal
    state: restarted

- name: Remove a service role
  cloudera.cluster.role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    type: GATEWAY
    state: absent
"""

RETURN = r"""
role:
  description: Details about the service role.
  type: dict
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
"""

from cm_client import (
    ApiRole,
    ApiRoleNameList,
    ClustersResourceApi,
    RoleConfigGroupsResourceApi,
    RolesResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    reconcile_config_list_updates,
    ClouderaManagerMutableModule,
    TagUpdates,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    get_base_role_config_group,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    create_role,
    parse_role_result,
    provision_service_role,
    read_role,
    read_roles,
    toggle_role_maintenance,
    toggle_role_state,
    RoleException,
)


class Role(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(Role, self).__init__(module)

        # Set the parameters
        self.cluster = self.get_param("cluster")
        self.service = self.get_param("service")
        self.name = self.get_param("name")
        self.cluster_hostname = self.get_param("cluster_hostname")
        self.cluster_host_id = self.get_param("cluster_host_id")
        self.maintenance = self.get_param("maintenance")
        self.config = self.get_param("config")
        self.role_config_group = self.get_param("role_config_group")
        self.tags = self.get_param("tags")
        self.type = self.get_param("type")
        self.state = self.get_param("state")
        self.purge = self.get_param("purge")
        self.skip_redacted = self.get_param("skip_redacted")

        # Initialize the return values
        self.changed = False
        self.diff = dict(before={}, after={})
        self.output = {}

        # Execute the logic
        self.process()

    @ClouderaManagerMutableModule.handle_process
    def process(self):
        if self.type:
            if not self.cluster_hostname and not self.cluster_host_id:
                self.module.fail_json(
                    msg="one of the following is required: %s"
                    % ", ".join(["cluster_hostname", "cluster_host_id"]),
                )

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
                self.module.fail_json(msg="Service does not exist: " + self.service)
            else:
                raise ex

        role_api = RolesResourceApi(self.api_client)
        current = None

        # If given the role identifier, get it or fail (is a read-only variable)
        if self.name:
            try:
                current = read_role(
                    api_client=self.api_client,
                    cluster_name=self.cluster,
                    service_name=self.service,
                    role_name=self.name,
                )
            except ApiException as ex:
                if ex.status != 404:
                    raise ex
                else:
                    return
        # Else look up the role by type and host
        else:
            current = next(
                iter(
                    read_roles(
                        api_client=self.api_client,
                        cluster_name=self.cluster,
                        service_name=self.service,
                        type=self.type,
                        hostname=self.cluster_hostname,
                        host_id=self.cluster_host_id,
                    ).items,
                ),
                None,
            )

        if self.state == "absent":
            if current:
                self.changed = True

                if self.module._diff:
                    self.diff = dict(before=parse_role_result(current), after=dict())

                if not self.module.check_mode:
                    role_api.delete_role(self.cluster, self.name, self.service)

        elif self.state in ["present", "restarted", "started", "stopped"]:
            # If it is a new role
            if not current:
                self.changed = True

                try:
                    role = create_role(
                        api_client=self.api_client,
                        cluster_name=self.cluster,
                        service_name=self.service,
                        role_type=self.type,
                        hostname=self.cluster_hostname,
                        host_id=self.cluster_host_id,
                        config=self.config,
                        role_config_group=self.role_config_group,
                        tags=self.tags,
                    )
                except RoleException as ex:
                    self.module.fail_json(msg=to_native(ex))

                if self.module._diff:
                    self.diff = dict(
                        before={},
                        after=role.to_dict(),
                    )

                if not self.module.check_mode:
                    current = provision_service_role(
                        api_client=self.api_client,
                        cluster_name=self.cluster,
                        service_name=self.service,
                        role=role,
                    )

                    if not current:
                        self.module.fail_json(
                            msg="Unable to create new role",
                            role=to_native(role.to_dict()),
                        )

                self.handle_maintenance(current)

            # Else it exists, so address any changes
            else:
                self.handle_maintenance(current)

                # Handle role override configurations
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
                            role_api.update_role_config(
                                cluster_name=self.cluster,
                                service_name=self.service,
                                role_name=current.name,
                                message=self.message,
                                body=updated_config,
                            )

                # Handle role config group
                if (
                    self.role_config_group is None
                    or self.role_config_group
                    != current.role_config_group_ref.role_config_group_name
                ):
                    # If None, move to the base role config group
                    if self.role_config_group is None:
                        base_rcg = get_base_role_config_group(
                            api_client=self.api_client,
                            cluster_name=self.cluster,
                            service_name=self.service,
                            role_type=current.type,
                        )

                        if (
                            current.role_config_group_ref.role_config_group_name
                            != base_rcg.name
                        ):
                            self.changed = True

                            if self.module._diff:
                                self.diff["before"].update(
                                    role_config_group=current.role_config_group_ref.role_config_group_name,
                                )
                                self.diff["after"].update(role_config_group=None)

                            if not self.module.check_mode:
                                RoleConfigGroupsResourceApi(
                                    self.api_client,
                                ).move_roles_to_base_group(
                                    cluster_name=self.cluster,
                                    service_name=self.service,
                                    body=ApiRoleNameList(items=[current.name]),
                                )
                    # Otherwise, move to the given role config group
                    else:
                        self.changed = True
                        if self.module._diff:
                            self.diff["before"].update(
                                role_config_group=current.role_config_group_ref.role_config_group_name,
                            )
                            self.diff["after"].update(
                                role_config_group=self.role_config_group,
                            )

                        if not self.module.check_mode:
                            RoleConfigGroupsResourceApi(self.api_client).move_roles(
                                cluster_name=self.cluster,
                                service_name=self.service,
                                role_config_group_name=self.role_config_group,
                                body=ApiRoleNameList(items=[current.name]),
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
                                role_api.delete_tags(
                                    cluster_name=self.cluster,
                                    service_name=self.service,
                                    role_name=self.name,
                                    body=tag_updates.deletions,
                                )

                            if tag_updates.additions:
                                role_api.add_tags(
                                    cluster_name=self.cluster,
                                    service_name=self.service,
                                    role_name=self.name,
                                    body=tag_updates.additions,
                                )

            # Handle state changes
            state_changed = toggle_role_state(
                api_client=self.api_client,
                role=current,
                state=self.state,
                check_mode=self.module.check_mode,
            )

            if state_changed is not None:
                self.changed = True
                if self.module._diff:
                    self.diff["before"].update(role_state=current.role_state)
                    self.diff["after"].update(role_state=state_changed)

            # If there are changes, get a fresh read
            if self.changed:
                self.output = parse_role_result(
                    read_role(
                        api_client=self.api_client,
                        cluster_name=self.cluster,
                        service_name=self.service,
                        role_name=current.name,
                    ),
                )
            else:
                self.output = parse_role_result(current)

        else:
            self.module.fail_json(msg=f"Invalid state: {self.state}")

    def handle_maintenance(self, role: ApiRole) -> None:
        if self.maintenance is not None:
            try:
                state_changed = toggle_role_maintenance(
                    api_client=self.api_client,
                    role=role,
                    maintenance=self.maintenance,
                    check_mode=self.module.check_mode,
                )
            except RoleException as ex:
                self.module.fail_json(msg=to_native(ex))

            if state_changed:
                self.changed = True
                if self.module._diff:
                    self.diff["before"].update(maintenance_mode=role.maintenance_mode)
                    self.diff["after"].update(maintenance_mode=self.maintenance)


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            service=dict(required=True, aliases=["service_name"]),
            name=dict(aliases=["role_name", "role"]),
            type=dict(aliases=["role_type"]),
            cluster_hostname=dict(aliases=["cluster_host"]),
            cluster_host_id=dict(),
            maintenance=dict(type="bool", aliases=["maintenance_mode"]),
            config=dict(type=dict, aliases=["parameters", "params"]),
            tags=dict(type=dict),
            role_config_group=dict(),
            purge=dict(type="bool", default=False),
            skip_redacted=dict(type="bool", default=False, aliases=["redacted"]),
            state=dict(
                default="present",
                choices=["present", "absent", "restarted", "started", "stopped"],
            ),
        ),
        mutually_exclusive=[
            ["type", "name"],
            ["cluster_hostname", "cluster_host_id"],
        ],
        required_one_of=[
            ["type", "name"],
        ],
        supports_check_mode=True,
    )

    result = Role(module)

    output = dict(
        changed=result.changed,
        role=result.output,
    )

    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
