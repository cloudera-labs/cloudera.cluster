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

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import ClouderaManagerModule

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: cm_endpoint_info
short_description: Discover the Cloudera Manager API endpoint
description:
  - Discover the Cloudera Manager API endpoint.
  - The module supports C(check_mode).
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
extends_documentation_fragment:
  - cloudera.cluster.cm_options
'''

EXAMPLES = r'''
---
# This will first try 'http://example.cloudera.com:7180' and will
# follow any redirects 
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

class ClouderaEndpointInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaEndpointInfo, self).__init__(module)
        
        # Initialize the return values
        self.endpoint = ""
        
        # Execute the logic
        self.process()
    
    @ClouderaManagerModule.handle_process
    def process(self):
        self.endpoint = self.api_client.host


def main():
    module = ClouderaManagerModule.ansible_module_discovery(
        supports_check_mode=True
    )

    result = ClouderaEndpointInfo(module)

    output = dict(
        changed=False,
        endpoint=result.endpoint,
    )

    if result.debug:
        output.update(
            sdk_out=result.log_out,
            sdk_out_lines=result.log_lines
        )

    module.exit_json(**output)


if __name__ == '__main__':
    main()
