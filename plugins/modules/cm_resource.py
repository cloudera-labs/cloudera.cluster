# Copyright 2023 Cloudera, Inc. All Rights Reserved.
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

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: cm_resource
short_description: Create, update, and delete resources from the Cloudera Manager API endpoint
description:
  - Create, update, and delete resources from ad-hoc Cloudera Manager API endpoint paths, i.e. unimplemented API calls.
  - This module only supports the C(POST), C(PUT), and C(DELETE) HTTP methods.
  - To retrieve details, i.e. read-only, from ad-hoc/unimplemented API endpoints, use the M(cloudera.cluster.cm_resource_info) module.
  - The module supports C(check_mode).
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
options:
  method:
    description:
      - HTTP method for the CM API endpoint path.
    type: str
    required: True
    choices:
        - DELETE
        - POST
        - PUT
  body:
    description:
      - HTTP body for the CM API endpoint call.
    type: dict
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - cloudera.cluster.cm_resource
"""

EXAMPLES = r"""
---
- name: Create a new local Cloudera Manager user
  cloudera.cluster.cm_resource:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    path: "/user"
    method: "POST"
    body:
      items:
        - name: new_user
          password: "Als*$ecU7e"

- name: Update a Cloudera Manager user
  cloudera.cluster.cm_resource:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    path: "/user/existing_user"
    method: "PUT"
    body:
      authRoles:
        - name: "ROLE_LIMITED"
        
- name: Delete a Cloudera Manager user using a custom SSL certificate
  host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    path: "/user/existing_user"
    ssl_ca_cert: "/path/to/ssl_ca.crt"
    method: "DELETE"
"""

RETURN = r"""
---
resources:
    description:
        - The results from the Cloudera Manager API endpoint call.
        - If the I(field) is found on the response object, its contents will be returned.
    type: list
    elements: complex
    returned: always
"""


class ClouderaResource(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaResource, self).__init__(module)

        # Set parameters
        self.method = self.get_param("method")
        self.path = self.get_param("path")
        self.query = self.get_param("query", dict())
        self.field = self.get_param("field")
        self.body = self.get_param("body")

        # Initialize the return values
        self.resources = []

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        if not self.module.check_mode:
            self.resources = self.call_api(
                self.path, self.method, self.query, self.field, self.body
            )


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            method=dict(required=True, type="str", choices=["POST", "PUT", "DELETE"]),
            path=dict(required=True, type="str"),
            query=dict(
                required=False, type="dict", aliases=["query_parameters", "parameters"]
            ),
            body=dict(required=False, type="dict"),
            field=dict(
                required=False, type="str", default="items", aliases=["return_field"]
            ),
        ),
        supports_check_mode=True,
    )

    result = ClouderaResource(module)

    output = dict(
        changed=False,
        resources=result.resources,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
