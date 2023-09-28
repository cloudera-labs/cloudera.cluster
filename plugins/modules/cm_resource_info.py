#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

import json

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import ClouderaManagerModule

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: cm_resource_info
short_description: Retrieve resources from the Cloudera Manager API endpoint
description:
  - Retrieve resources from ad-hoc Cloudera Manager API endpoint paths, i.e. unimplemented API calls.
  - This module only supports the C(GET) HTTP method.
  - To interact with ad-hoc/unimplemented API endpoints, use the M(cloudera.cluster.cm_resource) module.
  - The module supports C(check_mode).
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - cloudera.cluster.cm_resource
'''

EXAMPLES = r'''
---
- name: Gather details about all Cloudera Manager users
  cloudera.cluster.cm_resource_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    path: "/users"
'''

RETURN = r'''
---
resources:
    description:
        - The results from the Cloudera Manager API endpoint call.
        - If the I(field) is found on the response object, its contents will be returned.
    type: list
    elements: complex
    returned: always
'''

class ClouderaResourceInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaResourceInfo, self).__init__(module)
        
        # Set parameters
        self.path = self._get_param('path')
        self.query = self._get_param('query', dict())
        self.field = self._get_param('field')
        
        # Initialize the return values
        self.resources = []
        
        # Execute the logic
        self.process()
    
    @ClouderaManagerModule.handle_process
    def process(self):
        self.resources = self.call_api(self.path, 'GET', self.query, self.field)


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            path=dict(required=True, type='str'),
            query=dict(required=False, type='dict', aliases=['query_parameters', 'parameters']),
            field=dict(required=False, type='str', default='items', aliases=['return_field'])
        ),
        supports_check_mode=True
    )

    result = ClouderaResourceInfo(module)

    output = dict(
        changed=False,
        resources=result.resources,
    )

    if result.debug:
        output.update(
            sdk_out=result.log_out,
            sdk_out_lines=result.log_lines
        )

    module.exit_json(**output)


if __name__ == '__main__':
    main()
