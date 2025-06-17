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
module: cm_license
short_description: Activate the license for Cloudera Manager
description:
  - Activates the license if not already activated.
  - Return information about the acivate license.
author:
  - "Ronald Suplina (@rsuplina)"
requirements:
  - cm_client
"""

EXAMPLES = r"""
- name: Activate Cloudera Manager license
  cloudera.cluster.cm_license:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    license: "./files/license.txt"
"""

RETURN = r"""
cloudera_manager:
    description: Details about a active license
    type: dict
    contains:
        owner:
            description: Owner of the license
            type: str
            returned: optional
        uuid:
            description: Unique ID of the license
            type: bool
            returned: optional
        expiration:
            description: Expiration date of the license
            type: str
            returned: optional
        features:
            description: List of features within the license
            type: list
            returned: optional
        deactivation_date:
            description: Date until license is valid
            type: str
            returned: optional
        start_date:
            description: License activation date
            type: str
            returned: optional
"""

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from cm_client.rest import ApiException
from cm_client import ClouderaManagerResourceApi


class ClouderaLicense(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaLicense, self).__init__(module)
        self.license = self.get_param("license")
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):

        try:
            api_instance = ClouderaManagerResourceApi(self.api_client)

            self.cm_license_output = api_instance.read_license().to_dict()
            self.changed = False

        except ApiException as e:
            if e.status == 404:
                if not self.module.check_mode:

                    api_instance.update_license(license=self.license).to_dict()
                    self.cm_license_output = api_instance.read_license().to_dict()
                    self.changed = True

        except FileNotFoundError:
            self.cm_license_output = f"Error: File '{self.license}' not found."
            self.module.fail_json(msg=str(self.cm_license_output))


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(license=dict(required=True, type="path")),
        supports_check_mode=True,
    )

    result = ClouderaLicense(module)

    output = dict(
        changed=result.changed,
        cloudera_manager=result.cm_license_output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
