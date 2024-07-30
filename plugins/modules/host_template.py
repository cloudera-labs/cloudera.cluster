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
from ansible_collections.cloudera.cluster.plugins.module_utils.host_template_utils import (
    _parse_host_template_output,
)
from cm_client import (
    HostTemplatesResourceApi,
    ClustersResourceApi,
    ApiHostTemplate,
    ApiRoleConfigGroupRef,
    ApiClusterRef,
    ApiHostTemplateList,
)
from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: host_template
short_description: Configure a host template
description:
  - Creates a new host template or updates an existing one
  - The module supports C(check_mode).
author:
  - "Ronald Suplina (@rsuplina)"
requirements:
  - cm_client
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
  role_groups:
    description:
      - Names of the role configuration groups associated with the host template.
    type: list
    returned: yes
    aliases:
      - role_config_groups
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
"""

EXAMPLES = r"""
---
- name: Create host template
  cloudera.cluster.host_template
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: "base_cluster"
    name: "MyTemplate"
    role_groups: ["kafka-GATEWAY-BASE", "atlas-ATLAS_SERVER-BASE" , "hive_on_tez-GATEWAY-BASE"]

- name: Update host template
  cloudera.cluster.host_template
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: "base_cluster"
    name: "MyTemplate"
    role_groups: ["kafka-GATEWAY-BASE", "atlas-ATLAS_SERVER-BASE"]

- name: Remove host template
  cloudera.cluster.host_template
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: "base_cluster"
    name: "MyTemplate"
    state: "absent"
"""

RETURN = r"""
---
host_template:
  description:
    - Retrieve details about host template.
  type: dict
  elements: dict
  returned: always
  contains:
    name:
      description:
        - The name of the host template
      type: str
      returned: always
    cluster_name:
      description: A reference to the enclosing cluster.
      type: str
      returned: always
    role_groups:
      description:
        - The role config groups belonging to this host tempalte.
      type: list
      returned: always
"""


class ClouderaHostTemplate(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaHostTemplate, self).__init__(module)

        # Set the parameters
        self.cluster_name = self.get_param("cluster")
        self.name = self.get_param("name")
        self.role_groups = self.get_param("role_groups")
        self.state = self.get_param("state")

        # Initialize the return value
        self.host_template = []
        self.host_template_output = []
        self.changed = False
        self.diff = {}

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        host_temp_api_instance = HostTemplatesResourceApi(self.api_client)
        try:
            ClustersResourceApi(self.api_client).read_cluster(self.cluster_name)
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(
                    msg="Cluster does not exist: " + self.cluster_name
                )
            else:
                raise ex
        try:
            self.host_template = host_temp_api_instance.read_host_template(
                cluster_name=self.cluster_name,
                host_template_name=self.name,
            )
        except ApiException as ex:
            if ex.status == 404:
                pass
            else:
                raise ex

        if self.host_template:
            if self.module._diff:
                current = {
                    item.role_config_group_name
                    for item in self.host_template.role_config_group_refs
                }
                incoming = set(self.role_groups)
                self.diff.update(
                    before=list(current - incoming), after=list(incoming - current)
                )

        if self.state == "present":
            host_template_body = ApiHostTemplate(
                cluster_ref=ApiClusterRef(
                    cluster_name=self.cluster_name, display_name=self.cluster_name
                ),
                name=self.name,
                role_config_group_refs=[
                    ApiRoleConfigGroupRef(role_config_group_name=group)
                    for group in self.role_groups
                ],
            )
            if self.host_template:
                if not self.module.check_mode:
                    host_temp_api_instance.update_host_template(
                        cluster_name=self.cluster_name,
                        host_template_name=self.name,
                        body=host_template_body,
                    )
                    self.changed = True
            else:
                body = ApiHostTemplateList(items=[host_template_body])
                if not self.module.check_mode:
                    host_temp_api_instance.create_host_templates(
                        cluster_name=self.cluster_name, body=body
                    )
                    self.changed = True

            self.host_template_output = _parse_host_template_output(
                host_temp_api_instance.read_host_template(
                    cluster_name=self.cluster_name,
                    host_template_name=self.name,
                ).to_dict()
            )

        if self.state == "absent":
            if not self.module.check_mode:
                self.host_template_output = _parse_host_template_output(
                    host_temp_api_instance.delete_host_template(
                        cluster_name=self.cluster_name,
                        host_template_name=self.name,
                    ).to_dict()
                )
                self.changed = True


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, type="str", aliases=["cluster_name"]),
            name=dict(required=True, type="str"),
            role_groups=dict(
                required=False, type="list", aliases=["role_config_groups"]
            ),
            state=dict(
                type="str",
                default="present",
                choices=["present", "absent"],
            ),
        ),
        supports_check_mode=True,
        required_if=[
            ("state", "present", ("cluster", "role_groups")),
        ],
    )

    result = ClouderaHostTemplate(module)

    output = dict(
        changed=result.changed,
        host_template_output=result.host_template_output,
    )
    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
