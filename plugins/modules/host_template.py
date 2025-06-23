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
module: host_template
short_description: Manage a cluster host template
description:
  - Manage a cluster host template.
author:
  - "Webster Mudge (@wmudge)"
  - "Ronald Suplina (@rsuplina)"
version_added: "5.0.0"
options:
  cluster:
    description:
      - The associated cluster name.
    type: str
    required: yes
    aliases:
      - cluster_name
  name:
    description:
      - The name of the host template.
    type: str
    required: yes
    aliases:
      - host_template_name
      - host_template
      - template
  role_config_groups:
    description:
      - Names of the role configuration groups associated with the host template.
    type: list
    elements: dict
    required: yes
    suboptions:
      name:
        description:
          - The name of the custom role config group for the specified service.
          - Mutually exclusive with O(role_config_groups[].type).
        type: str
        required: no
      service:
        description:
          - The name of the service of the role config group, base or custom.
        type: str
        required: yes
        aliases:
          - service_name
      type:
        description:
          - The name of the role type of the base role config group for the specified service.
          - Mutually exclusive with O(role_config_groups[].name).
        type: str
        required: no
        aliases:
          - role_type
  purge:
    description:
      - Flag for whether the declared role config groups should append or overwrite any existing entries.
      - To clear all configuration overrides or tags, set O(role_config_groups={}), i.e. an empty dictionary, and set O(purge=True).
    type: bool
    default: False
  state:
    description:
      - The state of the host template.
    type: str
    required: no
    choices:
      - present
      - absent
    default: present
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
  - module: cloudera.cluster.host_template_info
"""

EXAMPLES = r"""
- name: Provision a host template with a base role config group assignment
  cloudera.cluster.host_template:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: "example_cluster"
    name: "Custom Template"
    role_config_groups:
      - type: DATANODE
        service: hdfs-service-1

- name: Provision a host template with a named (custom) role config group assignment
  cloudera.cluster.host_template:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: "example_cluster"
    name: "Custom Template"
    role_config_groups:
      - name: custom-zk-server
        service: zookeeper-service-1

- name: Update (append) a role config group to a host template
  cloudera.cluster.host_template:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: "example_cluster"
    name: "Custom Template"
    role_config_groups:
      - type: OZONE_DATANODE
        service: ozone-service-2

- name: Update (reset) the role config groups of a host template
  cloudera.cluster.host_template:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: "example_cluster"
    name: "Custom Template"
    role_config_groups:
      - type: DATANODE
        service: hdfs-service-1
      - type: OZONE_DATANODE
        service: ozone-service-2
    purge: true

- name: Remove a host template
  cloudera.cluster.host_template:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: "example_cluster"
    name: "Custom Template"
    state: "absent"
"""

RETURN = r"""
host_template:
  description: Details regarding the host template.
  type: dict
  returned: always
  contains:
    name:
      description:
        - The name of the host template.
      type: str
      returned: always
    cluster_name:
      description:
        - A reference to the enclosing cluster.
      type: str
      returned: always
    role_config_groups:
      description:
        - The role config groups associated with this host template, by role config group name.
      type: list
      elements: str
      returned: always
"""

from cm_client import (
    HostTemplatesResourceApi,
    ClustersResourceApi,
    ApiRoleConfigGroup,
    ApiRoleConfigGroupRef,
    ApiHostTemplateList,
    RoleConfigGroupsResourceApi,
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.host_template_utils import (
    create_host_template_model,
    parse_host_template,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    get_base_role_config_group,
)


class ClouderaHostTemplate(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaHostTemplate, self).__init__(module)

        # Set the parameters
        self.cluster = self.get_param("cluster")
        self.name = self.get_param("name")
        self.role_config_groups = self.get_param("role_config_groups")
        self.purge = self.get_param("purge")
        self.state = self.get_param("state")

        # Initialize the return values
        self.output = {}
        self.changed = False
        self.diff = {}

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        try:
            ClustersResourceApi(self.api_client).read_cluster(self.cluster)
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg="Cluster does not exist: " + self.cluster)
            else:
                raise ex

        host_template_api = HostTemplatesResourceApi(self.api_client)
        current = None

        try:
            current = host_template_api.read_host_template(
                cluster_name=self.cluster,
                host_template_name=self.name,
            )
        except ApiException as ex:
            if ex.status != 404:
                raise ex

        if self.state == "absent":
            if current:
                self.changed = True

                if self.module._diff:
                    self.diff = dict(before=parse_host_template(current), after=dict())

                if not self.module.check_mode:
                    host_template_api.delete_host_template(
                        cluster_name=self.cluster,
                        host_template_name=self.name,
                    )
        elif self.state == "present":
            rcg_api = RoleConfigGroupsResourceApi(self.api_client)

            # Find all of the role config group references
            incoming_rcgs = list[ApiRoleConfigGroup]()
            for rcg in self.role_config_groups:
                if rcg["name"] is not None:
                    custom_rcg = rcg_api.read_role_config_group(
                        cluster_name=self.cluster,
                        service_name=rcg["service"],
                        role_config_group_name=rcg["name"],
                    )
                    incoming_rcgs.append(custom_rcg)
                else:
                    base_rcg = get_base_role_config_group(
                        api_client=self.api_client,
                        cluster_name=self.cluster,
                        service_name=rcg["service"],
                        role_type=rcg["type"].upper(),
                    )
                    if base_rcg is None:
                        self.module.fail_json(
                            msg=f"Role type '{rcg['type']}' not found for service '{rcg['service']}' in cluster '{self.cluster}'"
                        )
                    incoming_rcgs.append(base_rcg)

            # If exists, modify
            if current:
                # Reconcile host template differences
                current_rcg_names = set(
                    [
                        rcg.role_config_group_name
                        for rcg in current.role_config_group_refs
                    ]
                )
                incoming_rcg_names = set([rcg.name for rcg in incoming_rcgs])

                additions = incoming_rcg_names - current_rcg_names
                deletions = set()

                if additions or self.purge:
                    updated_rcg_names = current_rcg_names | additions

                    if self.purge:
                        deletions = current_rcg_names - incoming_rcg_names
                        updated_rcg_names = updated_rcg_names - deletions

                    if additions or deletions:
                        self.changed = True

                        if self.module._diff:
                            current_diff = parse_host_template(current)
                            updated_diff = dict(**current_diff)
                            updated_diff.role_config_groups = updated_rcg_names
                            self.diff.update(
                                before=current_diff, after=dict(updated_diff)
                            )

                        current.role_config_group_refs = [
                            ApiRoleConfigGroupRef(rcg_name)
                            for rcg_name in updated_rcg_names
                        ]

                        if not self.module.check_mode:
                            current = host_template_api.update_host_template(
                                cluster_name=self.cluster,
                                host_template_name=self.name,
                                body=current,
                            )
            # Else, create
            else:
                self.changed = True

                created_host_template = create_host_template_model(
                    cluster_name=self.cluster,
                    name=self.name,
                    role_config_groups=incoming_rcgs,
                )

                if self.module._diff:
                    self.diff.update(
                        before=dict(), after=parse_host_template(created_host_template)
                    )

                if not self.module.check_mode:
                    current = host_template_api.create_host_templates(
                        cluster_name=self.cluster,
                        body=ApiHostTemplateList(items=[created_host_template]),
                    ).items[0]

            self.output = parse_host_template(current)
        else:
            self.module.fail_json(msg=f"Invalid state: {self.state}")


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            name=dict(
                required=True,
                aliases=["host_template_name", "host_template", "template"],
            ),
            role_config_groups=dict(
                type="list",
                elements="dict",
                options=dict(
                    name=dict(),
                    service=dict(required=True, aliases=["service_name"]),
                    type=dict(aliases=["role_type"]),
                ),
                mutually_exclusive=[
                    ("name", "type"),
                ],
            ),
            purge=dict(type="bool", default=False),
            state=dict(
                type="str",
                default="present",
                choices=["present", "absent"],
            ),
        ),
        required_if=[
            ("state", "present", ("cluster", "role_config_groups")),
        ],
        supports_check_mode=True,
    )

    result = ClouderaHostTemplate(module)

    output = dict(
        changed=result.changed,
        host_template=result.output,
    )
    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
