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
)
from cm_client import DataContextsResourceApi, ApiDataContextList

from cm_client import (
    ClustersResourceApi,
    ApiDataContext,
)
from cm_client.rest import ApiException
from ansible_collections.cloudera.cluster.plugins.module_utils.data_context_utils import (
    parse_data_context_result,
)

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: data_context
short_description: Create, update, or delete a data context
description:
  - Configure details of a specific data context.
  - Create a new data context.
  - Update an existing data context.
  - Delete a data context.
  - The module supports C(check_mode).
author:
  - "Ronald Suplina (@rsuplina)"
requirements:
  - cm-client >= 54
options:
  name:
    description:
      - The name of the data context.
    type: str
    required: yes
  cluster:
    description:
      - The name of the Cloudera Manager cluster.
    type: str
    required: no
  services:
    description:
      - A list of services that the data context will include.
    type: list
    required: no
  state:
    description:
      - If I(state=present), the data context will be created or updated.
      - If I(state=absent), the data context will be deleted
    type: str
    required: no
    default: present
    choices:
      - present
      - absent
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
"""

EXAMPLES = r"""
---
- name: Create a Data Context
  cloudera.cluster.data_context
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: "base_services"
    cluster: "example_cluster"
    services: ['hive','atlas','hdfs','ranger']
    state: present

- name: Delete a data context
  cloudera.cluster.data_context
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: "base_services"
    state: absent

- name: Update an existing data context
  cloudera.cluster.data_context
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: "base_services"
    cluster: "example_cluster"
    services: ['hive','atlas','hdfs']
    state: present
"""

RETURN = r"""
---
data_context:
  description:
    - A dictionary containing details of data contexts within the cluster.
  type: dict
  elements: complex
  returned: always
  contains:
    name:
      description:
        - The name of the data context.
      type: str
      returned: always
    display_name:
      description:
        - The display name of the data context.
      type: str
      returned: always
    nameservice:
      description:
        - The name service that data context belongs to.
      type: str
      returned: always
    created_time:
      description:
        - The timestamp indicating when the data context was created.
      type: str
      returned: always
    last_modified_time:
      description:
        - The timestamp indicating the last modification of the data context.
      type: str
      returned: always
    services:
      description:
        - The list of services associated with data context.
      type: list
      returned: always
    supported_service_types:
      description:
        - The list of supported services types within data context.
      type: list
      returned: always
    allowed_cluster_versions:
      description:
        - The list of allowed cluster versions within data context.
      type: list
      returned: always
    config_staleness_status:
      description:
        - Status of the configuration within data context.
      type: str
      returned: always
    client_config_staleness_status:
      description:
        - Status of the client configuration within data context.
      type: str
      returned: always
    health_summary:
      description:
        - The health status of the data context.
      type: str
      returned: always
"""


class ClouderaDataContext(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClouderaDataContext, self).__init__(module)

        # Set the parameters
        self.data_contex_name = self.get_param("name")
        self.cluster_name = self.get_param("cluster")
        self.services = self.get_param("services")
        self.state = self.get_param("state")
        # Initialize the return value
        self.data_context_output = []
        self.changed = False
        self.diff = {}
        # Execute the logic
        self.process()

    @ClouderaManagerMutableModule.handle_process
    def process(self):
        data_context_api = DataContextsResourceApi(self.api_client)
        existing = []

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
            existing = data_context_api.read_data_context(
                data_context_name=self.data_contex_name
            ).to_dict()
        except ApiException as ex:
            if ex.status == 500:
                pass
            else:
                raise ex

        if self.state == "present":
            if existing:
                existing_service = {
                    service["service_name"] for service in existing["services"]
                }
                incoming_service = set(self.services)
                if existing_service != incoming_service:
                    if self.module._diff:
                        self.diff.update(
                            before=list(existing_service - incoming_service),
                            after=list(incoming_service - existing_service),
                        )
                    services = [
                        {"serviceName": service, "clusterName": self.cluster_name}
                        for service in incoming_service
                    ]
                    if not self.module.check_mode:
                        update_data_context = data_context_api.update_data_context(
                            body=ApiDataContext(
                                name=self.data_contex_name, services=services
                            )
                        ).to_dict()
                        self.data_context_output = parse_data_context_result(
                            ApiDataContextList(items=[update_data_context])
                        )
                        self.changed = True
                else:
                    self.data_context_output = existing
            else:
                services = [
                    {"serviceName": service, "clusterName": self.cluster_name}
                    for service in self.services
                ]
                if not self.module.check_mode:
                    create_data_context = data_context_api.create_data_context(
                        body=ApiDataContext(
                            name=self.data_contex_name, services=services
                        )
                    ).to_dict()

                    self.data_context_output = parse_data_context_result(
                        ApiDataContextList(items=[create_data_context])
                    )
                    self.changed = True

        if self.state == "absent":
            if existing:
                if not self.module.check_mode:
                    data_context_api.delete_data_context(
                        data_context_name=self.data_contex_name
                    ).to_dict()
                    self.changed = True


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            name=dict(required=True, type="str"),
            cluster=dict(required=False, type="str", aliases=["cluster_name"]),
            services=dict(required=False, type="list"),
            state=dict(
                type="str",
                default="present",
                choices=["present", "absent"],
            ),
        ),
        supports_check_mode=True,
        required_if=[
            ("state", "present", ("cluster", "services"), False),
        ],
    )
    result = ClouderaDataContext(module)

    output = dict(
        changed=False,
        data_context=result.data_context_output,
    )
    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
