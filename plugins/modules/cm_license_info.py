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
    ClouderaManagerModule,
)
from cm_client.rest import ApiException
from cm_client import ClouderaManagerResourceApi

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: cm_license
short_description: Returns details about current license
description:
  - Returns details about current active license.
author:
  - "Ronald Suplina (@rsuplina)"
requirements:
  - cm_client
"""

EXAMPLES = r"""
---
- name: Get details about a license
  cloudera.cluster.cm_license_info:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
"""

RETURN = r"""
---
cloudera_manager:
    description: Details about an active license
    type: dict
    contains:
        owner:
            description: Owner of the active license
            type: str
            returned: optional
        uuid:
            description: Unique ID of the license
            type: bool
            returned: optional
        expiration:
            description: Expiration date of the license
            type: date
            returned: optional
        features:
            description: List of features within the  license
            type: list
            returned: optional
        deactivation_date:
            description: Date until license is valid
            type: date
            returned: optional
        start_date:
            description: License activation date
            type: date
            returned: optional
"""


class ClouderaLicenseInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaLicenseInfo, self).__init__(module)

        # Initialize the return values
        self.cm_license_info = dict()

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        try:
            api_instance = ClouderaManagerResourceApi(self.api_client)
            self.cm_license_output = api_instance.read_license().to_dict()
        except ApiException as e:
            if e.status == 404:
                self.cm_cluster_info = (f"Error: License not found.")
                self.module.fail_json(msg=str(self.cm_license_output)) 

def main():
    module = ClouderaManagerModule.ansible_module(supports_check_mode=False)

    result = ClouderaLicenseInfo(module)


    output = dict(
        changed=False,
        cloudera_manager=result.cm_license_output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
