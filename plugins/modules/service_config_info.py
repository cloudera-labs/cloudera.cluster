#!/usr/bin/python
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

DOCUMENTATION = r"""
module: service_config_info
short_description: Retrieve information about the configuration for a cluster service
description:
  - Gather configuration information about a service of a CDP cluster.
author:
  - "Webster Mudge (@wmudge)"
version_added: "4.4.0"
requirements:
  - cm_client
options:
  cluster:
    description:
      - The cluster to examine.
    type: str
    required: yes
    aliases:
      - cluster_name
  service:
    description:
      - The service to examine.
      - If the service does not exist, the module will return an empty result.
    type: str
    aliases:
      - service_name
      - name
  view:
    description:
      - The view to materialize.
    type: str
    default: summary
    choices:
        - summary
        - full
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
"""

EXAMPLES = r"""
- name: Gather the configuration details for a cluster service
  cloudera.cluster.service_config_info:
    host: "example.cloudera.host"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: knox

- name: Gather the configuration details in 'full' for a cluster service
  cloudera.cluster.service_config_info:
    host: "example.cloudera.host"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: ecs
    view: full
"""

RETURN = r"""
config:
  description: Service-wide configuration details about a cluster service.
  type: list
  elements: dict
  contains:
    name:
      description: The canonical name that identifies this configuration parameter.
      type: str
      returned: always
    value:
      description:
        - The user-defined value.
        - When absent, the default value (if any) will be used.
        - Can also be absent, when enumerating allowed configs.
      type: str
      returned: always
    required:
      description:
        - Whether this configuration is required for the service.
        - If any required configuration is not set, operations on the service may not work.
        - Available using I(view=full).
      type: bool
      returned: when supported
    default:
      description:
        - The default value.
        - Available using I(view=full).
      type: str
      returned: when supported
    display_name:
      description:
        - A user-friendly name of the parameters, as would have been shown in the web UI.
        - Available using I(view=full).
      type: str
      returned: when supported
    description:
      description:
        - A textual description of the parameter.
        - Available using I(view=full).
      type: str
      returned: when supported
    related_name:
      description:
        - If applicable, contains the related configuration variable used by the source project.
        - Available using I(view=full).
      type: str
      returned: when supported
    sensitive:
      description:
        - Whether this configuration is sensitive, i.e. contains information such as passwords, which might affect how the value of this configuration might be shared by the caller.
      type: bool
      returned: when supported
    validation_state:
      description:
        - State of the configuration parameter after validation.
        - Available using I(view=full).
      type: str
      returned: when supported
      sample:
        - OK
        - WARNING
        - ERROR
    validation_message:
      description:
        - A message explaining the parameter's validation state.
        - Available using I(view=full).
      type: str
      returned: when supported
    validation_warnings_suppressed:
      description:
        - Whether validation warnings associated with this parameter are suppressed.
        - In general, suppressed validation warnings are hidden in the Cloudera Manager UI.
        - Configurations that do not produce warnings will not contain this field.
        - Available using I(view=full).
      type: bool
      returned: when supported
"""

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)

from cm_client import (
    ClustersResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException


class ClusterServiceConfigInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClusterServiceConfigInfo, self).__init__(module)

        # Set the parameters
        self.cluster = self.get_param("cluster")
        self.service = self.get_param("service")
        self.view = self.get_param("view")

        # Initialize the return values
        self.config = []

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

        api_instance = ServicesResourceApi(self.api_client)

        try:
            results = api_instance.read_service_config(
                cluster_name=self.cluster,
                service_name=self.service,
                view=self.view,
            )

            self.config = [s.to_dict() for s in results.items]
        except ApiException as e:
            if e.status != 404:
                raise e


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            service=dict(required=True, aliases=["service_name", "name"]),
            view=dict(
                default="summary",
                choices=["summary", "full"],
            ),
        ),
        supports_check_mode=True,
    )

    result = ClusterServiceConfigInfo(module)

    output = dict(
        changed=False,
        config=result.config,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
