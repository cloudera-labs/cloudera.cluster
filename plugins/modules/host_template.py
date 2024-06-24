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
  name:
    description:
      - The associated cluster name.
    type: str
    required: yes
    aliases:
      - cluster_name
  host_template_name:
    description:
      - The name of the host template.
    type: str
    required: yes
  roleConfigGroupRefs:
    description:
      - The names of the role config groups
    type: list
    returned: yes
"""

EXAMPLES = r"""
---
- name: Create host template 
  cloudera.cluster.host_template
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: "base_cluster"
    role_configs_groups: ["kafka-GATEWAY-BASE", "atlas-ATLAS_SERVER-BASE" , "hive_on_tez-GATEWAY-BASE"]

- name: Update host template 
  cloudera.cluster.host_template
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: "base_cluster"
    role_configs_groups: ["kafka-GATEWAY-BASE", "atlas-ATLAS_SERVER-BASE"]
"""

RETURN = r"""
---
cloudera_manager:
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
    clusterRef:
      description: A reference to the enclosing cluster.
      type: dict
      returned: always
    roleConfigGroupRefs:
      description:
        - The role config groups belonging to this host tempalte.
      type: list
      returned: always
"""


class ClouderaHostTemplate(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaHostTemplate, self).__init__(module)

        # Set the parameters
        self.cluster_name = self.get_param("name")
        self.host_template_name = self.get_param("host_template_name")
        self.role_configs_groups = self.get_param("role_configs_groups")

        # Initialize the return value
        self.host_template = []
        self.host_template_output = []

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

        if not self.module.check_mode:
            try:
                self.host_template = host_temp_api_instance.read_host_template(
                    cluster_name=self.cluster_name,
                    host_template_name=self.host_template_name,
                )
            except ApiException as ex:
                if ex.status == 404:
                    pass
                else:
                    raise ex

            host_template = ApiHostTemplate(
                cluster_ref=ApiClusterRef(
                    cluster_name=self.cluster_name, display_name=self.cluster_name
                ),
                name=self.host_template_name,
                role_config_group_refs=[
                    ApiRoleConfigGroupRef(role_config_group_name=group)
                    for group in self.role_configs_groups
                ],
            )
            if self.host_template:
                self.host_template_output = host_temp_api_instance.update_host_template(
                    cluster_name=self.cluster_name,
                    host_template_name=self.host_template_name,
                    body=host_template,
                )
                self.changed = True
            else:
                body = ApiHostTemplateList(items=[host_template])
                self.host_template_output = (
                    host_temp_api_instance.create_host_templates(
                        cluster_name=self.cluster_name, body=body
                    )
                )
                self.changed = True

            self.host_template_output = host_temp_api_instance.read_host_template(
                cluster_name=self.cluster_name,
                host_template_name=self.host_template_name,
            ).to_dict()


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            name=dict(required=True, type="str", aliases=["cluster_name"]),
            host_template_name=dict(required=True, type="str"),
            role_configs_groups=dict(required=True, type="list"),
        ),
        supports_check_mode=True,
    )

    result = ClouderaHostTemplate(module)

    output = dict(
        changed=result.changed,
        host_template_output=result.host_template_output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
