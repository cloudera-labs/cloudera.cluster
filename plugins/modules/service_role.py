# -*- coding: utf-8 -*-

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
    ClouderaManagerMutableModule,
    resolve_tag_updates,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    parse_role_result,
)

from cm_client import (
    ApiEntityTag,
    ApiHostRef,
    ApiRole,
    ApiRoleList,
    ApiRoleNameList,
    ClustersResourceApi,
    HostsResourceApi,
    RoleCommandsResourceApi,
    RolesResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: service_role
short_description: Manage a service role in cluster
description:
  - Manage a service role in a cluster.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm-client
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
      - The role name.
      - If not specified, the role name will be auto-generated on creation.
    type: str
    aliases:
      - role_name
      - name
  cluster_hostname:
    description:
      - The hostname of a cluster instance for the role.
      - Mutually exclusive with I(cluster_host_id).
    type: str
    aliases:
      - cluster_host
  cluster_host_id:
    description:
      - The host ID of a cluster instance for the role.
      - Mutually exclusive with I(cluster_hostname).
    type: str
  type:
    description:
      - A role type for the role.
      - Required if the I(state) creates a new role.
    type: str
    aliases:
      - role_type
  maintenance:
    description:
      - Flag for whether the role should be in maintenance mode.
    type: bool
    aliases:
      - maintenance_mode
  tags:
    description:
      - A set of tags applied to the role.
      - To unset a tag, use C(None) as its value.
    type: dict
  purge:
    description:
      - Flag for whether the declared role tags should append or overwrite any existing tags.
      - To clear all tags, set I(tags={}), i.e. an empty dictionary, and I(purge=True).
    type: bool
    default: False
  state:
    description:
      - The state of the role.
      - Note, if the declared state is invalid for the role, for example, the role is a C(HDFS GATEWAY), the module will return an error.
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
"""

EXAMPLES = r"""
---
- name: Establish a service role (auto-generated name)
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    type: GATEWAY
    cluster_hostname: worker-01.cloudera.internal

- name: Establish a service role (defined name)
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    type: GATEWAY
    name: example-gateway
    cluster_hostname: worker-01.cloudera.internal

- name: Set a service role to maintenance mode
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    name: example-gateway
    maintenance: yes

- name: Update (append) tags to a service role
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    name: example-gateway
    tags:
      tag_one: value_one
      tag_two: value_two

- name: Set (purge) tags to a service role
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    cluster: example-cluster
    service: example-hdfs
    name: example-gateway
    tags:
      tag_three: value_three
    purge: yes

- name: Remove all tags on a service role
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    name: example-gateway
    tags: {}
    purge: yes

- name: Start a service role
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    name: example-gateway
    state: started

- name: Force a restart to a service role
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    name: example-gateway
    state: restarted

- name: Start a service role
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    name: example-gateway
    state: started

- name: Remove a service role
  cloudera.cluster.service_role:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-hdfs
    name: example-gateway
    state: absent
"""

RETURN = r"""
---
role:
  description: Details about the service role.
  type: dict
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


class ClusterServiceRole(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClusterServiceRole, self).__init__(module)

        # Set the parameters
        self.cluster = self.get_param("cluster")
        self.service = self.get_param("service")
        self.role = self.get_param("role")
        self.cluster_hostname = self.get_param("cluster_hostname")
        self.cluster_host_id = self.get_param("cluster_host_id")
        self.maintenance = self.get_param("maintenance")
        self.tags = self.get_param("tags")
        self.type = self.get_param("type")
        self.state = self.get_param("state")
        self.purge = self.get_param("purge")

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

        try:
            ServicesResourceApi(self.api_client).read_service(
                self.cluster, self.service
            )
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg="Service does not exist: " + self.service)
            else:
                raise ex

        api_instance = RolesResourceApi(self.api_client)
        existing = None

        if self.role:
            try:
                existing = api_instance.read_role(self.cluster, self.role, self.service)
            except ApiException as ex:
                if ex.status != 404:
                    raise ex

        if self.state == "absent":
            if existing:
                self.changed = True
                if not self.module.check_mode:
                    api_instance.delete_role(self.cluster, self.role, self.service)

        elif self.state in ["present", "restarted", "started", "stopped"]:

            if existing:
                if self.type and self.type != existing.type:
                    # Destroy and rebuild
                    self.changed = True

                    if not self.module.check_mode:
                        api_instance.delete_role(self.cluster, self.role, self.service)
                        self.cluster_host_id = existing.host_ref.host_id
                        self.cluster_hostname = existing.host_ref.hostname
                        self.create_role(api_instance)
                else:
                    # Update existing

                    # Maintenance
                    if (
                        self.maintenance is not None
                        and self.maintenance != existing.maintenance_mode
                    ):
                        self.changed = True

                        if self.module._diff:
                            self.diff["before"].update(
                                maintenance_mode=existing.maintenance_mode
                            )
                            self.diff["after"].update(maintenance_mode=self.maintenance)

                        if not self.module.check_mode:
                            if self.maintenance:
                                maintenance_cmd = api_instance.enter_maintenance_mode(
                                    self.cluster, self.role, self.service
                                )
                            else:
                                maintenance_cmd = api_instance.exit_maintenance_mode(
                                    self.cluster, self.role, self.service
                                )

                            if maintenance_cmd.success is False:
                                self.module.fail_json(
                                    msg=f"Unable to set Maintenance mode to '{self.maintenance}': {maintenance_cmd.result_message}"
                                )

                    # Tags
                    if self.tags:
                        (delta_add, delta_del) = resolve_tag_updates(
                            {t.name: t.value for t in existing.tags},
                            self.tags,
                            self.purge,
                        )

                        if delta_add or delta_del:
                            self.changed = True

                            if self.module._diff:
                                self.diff["before"].update(tags=delta_del)
                                self.diff["after"].update(tags=delta_add)

                            if not self.module.check_mode:
                                if delta_del:
                                    api_instance.delete_tags(
                                        self.cluster,
                                        self.role,
                                        self.service,
                                        body=[
                                            ApiEntityTag(k, v)
                                            for k, v in delta_del.items()
                                        ],
                                    )
                                if delta_add:
                                    api_instance.add_tags(
                                        self.cluster,
                                        self.role,
                                        self.service,
                                        body=[
                                            ApiEntityTag(k, v)
                                            for k, v in delta_add.items()
                                        ],
                                    )

                    # TODO Config

                    if self.state == "started" and existing.role_state != "STARTED":
                        self.changed = True

                        if self.module._diff:
                            self.diff["before"].update(role_state=existing.role_state)
                            self.diff["after"].update(role_state="STARTED")

                        if not self.module.check_mode:
                            self.start_role(self.role)

                    elif self.state == "stopped" and existing.role_state not in [
                        "STOPPED",
                        "NA",
                    ]:
                        self.changed = True

                        if self.module._diff:
                            self.diff["before"].update(role_state=existing.role_state)
                            self.diff["after"].update(role_state="STOPPED")

                        if not self.module.check_mode:
                            self.stop_role(self.role)

                    elif self.state == "restarted":
                        self.changed = True

                        if self.module._diff:
                            self.diff["before"].update(role_state=existing.role_state)
                            self.diff["after"].update(role_state="STARTED")

                        if not self.module.check_mode:
                            restart_cmds = RoleCommandsResourceApi(
                                self.api_client
                            ).restart_command(
                                self.cluster,
                                self.service,
                                body=ApiRoleNameList(items=[self.role]),
                            )

                            if restart_cmds.errors:
                                error_msg = "\n".join(restart_cmds.errors)
                                self.module.fail_json(msg=error_msg)

                            for c in restart_cmds.items:
                                # Not in parallel, but should only be a single command
                                self.wait_command(c)

                    if self.changed:
                        self.output = parse_role_result(
                            api_instance.read_role(
                                self.cluster, self.role, self.service, view="full"
                            )
                        )
                    else:
                        self.output = parse_role_result(existing)
            else:
                # Role doesn't exist
                self.create_role(api_instance)

        else:
            self.module.fail_json(msg=f"Invalid state: {self.state}")

    def create_role(self, api_instance):
        missing_params = []

        if self.type is None:
            missing_params.append("type")

        if self.cluster_hostname is None and self.cluster_host_id is None:
            missing_params += ["cluster_hostname", "cluster_host_id"]

        if missing_params:
            self.module.fail_json(
                msg=f"Role does not exist, missing required arguments: {', '.join(sorted(missing_params)) }"
            )

        payload = ApiRole(type=str(self.type).upper())

        # Name
        if self.role:
            payload.name = self.role

        # Host assignment
        if self.cluster_host_id is None or self.cluster_hostname is None:
            host = None

            if self.cluster_hostname:
                host = next(
                    (
                        h
                        for h in HostsResourceApi(self.api_client).read_hosts().items
                        if h.hostname == self.cluster_hostname
                    ),
                    None,
                )
            else:
                try:
                    host = HostsResourceApi(self.api_client).read_host(
                        self.cluster_host_id
                    )
                except ApiException as ex:
                    if ex.status != 404:
                        raise ex

            if host is None:
                self.module.fail_json(msg="Invalid host reference")

            payload.host_ref = ApiHostRef(host.host_id, host.hostname)
        else:
            payload.host_ref = ApiHostRef(self.cluster_host_id, self.cluster_hostname)

        # Tags
        if self.tags:
            payload.tags = [ApiEntityTag(k, v) for k, v in self.tags.items()]

        # TODO Config

        self.changed = True

        if self.module._diff:
            self.diff = dict(
                before={},
                after=payload.to_dict(),
            )

        if not self.module.check_mode:
            created_role = next(
                (
                    iter(
                        api_instance.create_roles(
                            self.cluster,
                            self.service,
                            body=ApiRoleList([payload]),
                        ).items
                    )
                ),
                {},
            )

            refresh = False

            # Maintenance
            if self.maintenance:
                refresh = True

                if self.module._diff:
                    self.diff["after"].update(maintenance_mode=True)

                maintenance_cmd = api_instance.enter_maintenance_mode(
                    self.cluster, created_role.name, self.service
                )

                if maintenance_cmd.success is False:
                    self.module.fail_json(
                        msg=f"Unable to set Maintenance mode to '{self.maintenance}': {maintenance_cmd.result_message}"
                    )

            if self.state in ["started", "restarted"]:
                refresh = True
                self.start_role(created_role.name)

            elif self.state == "stopped":
                refresh = True
                self.stop_role(created_role.name)

            if refresh:
                self.output = parse_role_result(
                    api_instance.read_role(
                        self.cluster,
                        created_role.name,
                        self.service,
                        view="full",
                    )
                )
            else:
                self.output = parse_role_result(created_role)

    def start_role(self, role_name: str):
        start_cmds = RoleCommandsResourceApi(self.api_client).start_command(
            self.cluster,
            self.service,
            body=ApiRoleNameList(items=[role_name]),
        )

        if start_cmds.errors:
            error_msg = "\n".join(start_cmds.errors)
            self.module.fail_json(msg=error_msg)

        for c in start_cmds.items:
            # Not in parallel, but should only be a single command
            self.wait_command(c)

    def stop_role(self, role_name: str):
        stop_cmds = RoleCommandsResourceApi(self.api_client).stop_command(
            self.cluster,
            self.service,
            body=ApiRoleNameList(items=[role_name]),
        )

        if stop_cmds.errors:
            error_msg = "\n".join(stop_cmds.errors)
            self.module.fail_json(msg=error_msg)

        for c in stop_cmds.items:
            # Not in parallel, but should only be a single command
            self.wait_command(c)


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            service=dict(required=True, aliases=["service_name"]),
            role=dict(aliases=["role_name", "name"]),
            cluster_hostname=dict(aliases=["cluster_host"]),
            cluster_host_id=dict(),
            maintenance=dict(type="bool", aliases=["maintenance_mode"]),
            tags=dict(type=dict),
            purge=dict(type="bool", default=False),
            type=dict(),
            state=dict(
                default="present",
                choices=["present", "absent", "restarted", "started", "stopped"],
            ),
        ),
        mutually_exclusive=[
            ["cluster_hostname", "cluster_host_id"],
        ],
        supports_check_mode=True,
    )

    result = ClusterServiceRole(module)

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
