#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2022 Cloudera, Inc. All Rights Reserved.
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
short_description: Retrieve details from the Cloudera Manager API endpoint
description:
  - Retrieve ad-hoc information from the Cloudera Manager API endpoint, i.e. unimplemented API calls.
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
'''

EXAMPLES = r'''
---
# 
- name: Gather details using auto-discovery
  cloudera.cluster.cm_endpoint_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
  register: cm_endpoint
'''

RETURN = r'''
---
endpoint:
    description: The discovered Cloudera Manager API endpoint
    type: str
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
        path_params = self.query
        query_params = []
        header_params = {}
        header_params['Accept'] = self.api_client.select_header_accept(['application/json'])
        results =self.api_client.call_api(self.path, 
                                          'GET',
                                          path_params,
                                          query_params,
                                          header_params,
                                          auth_settings=['basic'],
                                          _preload_content=False)
        if results[1] == 200:
            data = json.loads(results[0].data.decode('utf-8'))
            if self.field in data:
                data = data[self.field]
            if type(data) is list:
                self.resources = data
            else:
                self.resources = [data]
        else:
            self.module.fail_json(msg="Error querying CM resource", status_code=results[1])

def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            path=dict(required=True, type='str'),
            query=dict(required=False, type='dict', aliases=['query_parameters', 'parameters']),
            #headers=dict
            #params=dict
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
