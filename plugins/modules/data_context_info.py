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
module: data_context_info
short_description: Retrieve details of data contexts
description:
  - Retrieve details of a specific data context or all data contexts within the Cloudera Manager.
author:
  - "Ronald Suplina (@rsuplina)"
version_added: "5.0.0"
requirements:
  - cm_client
options:
  name:
    description:
      - The name of the data context.
    type: str
    required: no
    aliases:
      - context_name
      - data_context_name
"""

EXAMPLES = r"""
- name: Gather details about specific data context
  cloudera.cluster.data_context_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: "SDX"

- name: Gather details about all data contexts within the cluster
  cloudera.cluster.data_context_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
"""

RETURN = r"""
data_context_info:
  description:
    - List of data contexts within the cluster.
  type: list
  elements: dict
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

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerMutableModule,
)
from cm_client import DataContextsResourceApi, ApiDataContextRef, ApiDataContextList

from cm_client.rest import ApiException
from ansible_collections.cloudera.cluster.plugins.module_utils.data_context_utils import (
    parse_data_context_result,
)


class ClouderaDataContextInfo(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClouderaDataContextInfo, self).__init__(module)

        # Set the parameters
        self.data_context_name = self.get_param("name")

        # Initialize the return value
        self.data_context_info = []

        # Execute the logic
        self.process()

    @ClouderaManagerMutableModule.handle_process
    def process(self):
        data_context_api = DataContextsResourceApi(self.api_client)
        if self.data_context_name:
            try:
                data_contex = data_context_api.read_data_context(
                    data_context_name=self.data_context_name,
                ).to_dict()
                self.data_context_info = parse_data_context_result(
                    ApiDataContextList(items=[data_contex]),
                )
            except ApiException as ex:
                if ex.status != 500:
                    raise ex
        else:
            data_contexts_info = data_context_api.read_data_contexts().to_dict()

            self.data_context_info = parse_data_context_result(
                ApiDataContextList(items=data_contexts_info.get("items", [])),
            )


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            name=dict(
                required=False,
                type="str",
                aliases=["context_name", "data_context_name"],
            ),
        ),
        supports_check_mode=False,
    )
    result = ClouderaDataContextInfo(module)

    output = dict(
        changed=False,
        data_context_info=result.data_context_info,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
