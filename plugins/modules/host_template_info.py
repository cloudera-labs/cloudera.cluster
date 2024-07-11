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
from cm_client import HostTemplatesResourceApi, ClustersResourceApi
from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: host_template_info
short_description: Retrieve details of host templates.
description:
  - Collects detailed information about individual or all host templates.
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
    required: no
"""

EXAMPLES = r"""
---
- name: Retrieve the defailts about a specific host template
  cloudera.cluster.host_template_info
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: "cfm_cluster"
    name: "cfm_host_template"

- name: Retrieve the details about all host templates within the cluster
  cloudera.cluster.host_template_info
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: "cfm_cluster"
"""

RETURN = r"""
---
host_template_info:
  description:
    - Details about host template.
  type: list
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
      type: dict
      returned: always
    role_config_group_refs:
      description:
        - The names of the role config groups
      type: list
      returned: always
"""


class ClouderaHostTemplateInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaHostTemplateInfo, self).__init__(module)

        # Set the parameters
        self.cluster_name = self.get_param("cluster")
        self.name = self.get_param("name")

        # Initialize the return value
        self.host_templates_output = []

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        try:
            ClustersResourceApi(self.api_client).read_cluster(self.cluster_name)
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(
                    msg="Cluster does not exist: " + self.cluster_name
                )
            else:
                raise ex

        host_temp_api_instance = HostTemplatesResourceApi(self.api_client)
        if self.name:
            try:
                self.host_templates_output = host_temp_api_instance.read_host_template(
                    cluster_name=self.cluster_name,
                    host_template_name=self.name,
                ).to_dict()
            except ApiException as ex:
                if ex.status == 404:
                    self.module.fail_json(
                        msg="Host Template does not exist: " + self.name
                    )
                else:
                    raise ex

        else:
            self.host_templates_output = host_temp_api_instance.read_host_templates(
                cluster_name=self.cluster_name
            ).items


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, type="str", aliases=["cluster_name"]),
            name=dict(required=False, type="str"),
        ),
        supports_check_mode=True,
    )

    result = ClouderaHostTemplateInfo(module)

    output = dict(
        changed=False,
        host_templates_output=result.host_templates_output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
