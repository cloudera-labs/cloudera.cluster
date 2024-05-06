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

import json

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerMutableModule,
    resolve_parameter_updates,
)

from cm_client import (
    ApiConfig,
    ApiServiceConfig,
    ClustersResourceApi,
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
module: service_config
short_description: Manage a service configuration in cluster 
description:
  - Manage a service configuration (service-wide) in a cluster.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
options:
  parameters:
    description:
      - The service-wide configuration to set.
      - To unset a parameter, use C(None) as the value.
    type: dict
    required: yes
    aliases:
      - params
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
  - cloudera.cluster.purge
  - cloudera.cluster.message
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
"""

EXAMPLES = r"""
---
- name: Update (append) several service-wide parameters
  cloudera.cluster.service_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-service
    parameters:
      a_configuration: "schema://host:port"
      another_configuration: 234

- name: Reset a service-wide parameter
  cloudera.cluster.service_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-service
    parameters:
      some_conf: None

- name: Update (purge) service-wide parameters
  cloudera.cluster.service_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-service
    parameters:
      config_one: ValueOne
      config_two: 4567
    purge: yes
    
- name: Reset all service-wide parameters
  cloudera.cluster.service_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-service
    parameters: {}
    purge: yes
"""

RETURN = r"""
---
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


class ClusterServiceConfig(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClusterServiceConfig, self).__init__(module)

        # Set the parameters
        self.cluster = self.get_param("cluster")
        self.service = self.get_param("service")
        self.params = self.get_param("parameters")
        self.purge = self.get_param("purge")
        self.view = self.get_param("view")

        # Initialize the return value
        self.changed = False
        self.diff = {}
        self.config = []

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

        refresh = True
        api_instance = ServicesResourceApi(self.api_client)

        try:
            existing = api_instance.read_service_config(self.cluster, self.service)
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg=json.loads(ex.body)["message"])
            else:
                raise ex

        current = {r.name: r.value for r in existing.items}
        incoming = {k: str(v) if v is not None else v for k, v in self.params.items()}

        change_set = resolve_parameter_updates(current, incoming, self.purge)

        if change_set:
            self.changed = True

            if self.module._diff:
                self.diff = dict(
                    before={
                        k: current[k] if k in current else None
                        for k in change_set.keys()
                    },
                    after=change_set,
                )

            if not self.module.check_mode:
                body = ApiServiceConfig(
                    items=[ApiConfig(name=k, value=v) for k, v in change_set.items()]
                )

                self.config = [
                    p.to_dict()
                    for p in api_instance.update_service_config(
                        self.cluster, self.service, message=self.message, body=body
                    ).items
                ]

                if self.view == "full":
                    refresh = False

        if refresh:
            self.config = [
                p.to_dict()
                for p in api_instance.read_service_config(
                    self.cluster, self.service, view=self.view
                ).items
            ]


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            service=dict(required=True, aliases=["service_name", "name"]),
            parameters=dict(type="dict", required=True, aliases=["params"]),
            purge=dict(type="bool", default=False),
            view=dict(
                default="summary",
                choices=["summary", "full"],
            ),
        ),
        supports_check_mode=True,
    )

    result = ClusterServiceConfig(module)

    output = dict(
        changed=result.changed,
        config=result.config,
    )

    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
