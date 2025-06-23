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
module: host_template_info
short_description: Retrieve details regarding a cluster's host templates.
description:
  - Collects detailed information about individual or all host templates for a cluster.
author:
  - "Ronald Suplina (@rsuplina)"
  - "Webster Mudge (@wmudge)"
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
    required: no
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
  - module: cloudera.cluster.host_template
"""

EXAMPLES = r"""
- name: Retrieve the defailts about a specific host template
  cloudera.cluster.host_template_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: "example_cluster"
    name: "example_host_template"

- name: Retrieve the details about all host templates within the cluster
  cloudera.cluster.host_template_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: "example_cluster"
"""

RETURN = r"""
host_templates:
  description: List of details about the host templates.
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
      description:
        - A reference to the enclosing cluster.
      type: dict
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
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.host_template_utils import (
    parse_host_template,
)


class ClouderaHostTemplateInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaHostTemplateInfo, self).__init__(module)

        # Set the parameters
        self.cluster_name = self.get_param("cluster")
        self.name = self.get_param("name")

        # Initialize the return value
        self.output = []

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

        host_template_api = HostTemplatesResourceApi(self.api_client)

        if self.name:
            try:
                self.output.append(
                    parse_host_template(
                        host_template_api.read_host_template(
                            cluster_name=self.cluster_name,
                            host_template_name=self.name,
                        )
                    )
                )
            except ApiException as ex:
                if ex.status != 404:
                    raise ex

        else:
            self.output = [
                parse_host_template(ht)
                for ht in host_template_api.read_host_templates(
                    cluster_name=self.cluster_name
                ).items
            ]


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
        host_templates=result.output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
