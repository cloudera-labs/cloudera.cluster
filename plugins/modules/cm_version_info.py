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

from cm_client import ClouderaManagerResourceApi

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: cm_version_info
short_description: Gather information about Cloudera Manager
description:
  - Gather information about the Cloudera Manager instance.
  - The module supports C(check_mode).
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
"""

EXAMPLES = r"""
---
- name: Gather details using an endpoint URL
  cloudera.cluster.cm_version:
    url: "https://example.cloudera.com:7183/api/v49"
    username: "jane_smith"
    password: "S&peR4Ec*re"
  register: cm_output
 
# This will first try 'http://example.cloudera.com:7180' and will
# follow any redirects 
- name: Gather details using auto-discovery
  cloudera.cluster.cm_version:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
  register: cm_discovery
"""

RETURN = r"""
---
cloudera_manager:
    description: Details for the Cloudera Manager instance
    type: dict
    contains:
        version:
            description: The Cloudera Manager version.
            type: str
            returned: optional
        snapshot:
            description: Whether this build is a development snapshot.
            type: bool
            returned: optional
        build_user:
            description: The user performing the build.
            type: str
            returned: optional
        build_timestamp:
            description: Build timestamp.
            type: str
            returned: optional
        git_hash:
            description: Source control management hash.
            type: str
            returned: optional
"""


class ClouderaManagerVersionInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaManagerVersionInfo, self).__init__(module)

        # Initialize the return values
        self.version = dict()

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        api_instance = ClouderaManagerResourceApi(self.api_client)
        self.version = api_instance.get_version().to_dict()


def main():
    module = ClouderaManagerModule.ansible_module(supports_check_mode=True)

    result = ClouderaManagerVersionInfo(module)

    output = dict(
        changed=False,
        cloudera_manager=result.version,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
