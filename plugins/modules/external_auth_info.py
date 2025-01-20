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

from ansible_collections.cloudera.cluster.plugins.module_utils.external_auth_utils import (
    FREEIPA_EXTERNAL_CONFIGS,
    KERBEROS_EXTERNAL_CONFIGS,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)


DOCUMENTATION = r"""
---
module: external_auth_info
short_description: Retrieves external authorizations details.
description:
  - Retrieves configuration details and external authorization settings for FreeIPA and Kerberos.
author:
  - "Ronald Suplina (@rsuplina)"
options:
  type:
    description:
      - The type of the external configurations to display.
    type: str
    required: no
    choices:
      - freeipa
      - kerberos
requirements:
  - cm_client
"""

EXAMPLES = r"""
---
- name: Get details about FreeIpa external configurations
  cloudera.cluster.external_auth_info:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: "freeipa"

- name: Get details about Kerberos external configurations
  cloudera.cluster.external_auth_info:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: "kerberos"

- name: Get details for all external configurations
  cloudera.cluster.external_auth_info:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"

"""

RETURN = r"""
---
external_auth_info:
    description: A dictionary containing external authentication configuration details. 
    type: dict
    returned: always

"""


class ClouderaExternalAuthInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaExternalAuthInfo, self).__init__(module)

        # Set the parameters
        self.type = self.get_param("type")

        # Initialize the return values
        self.external_auth_info_output = []

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        existing = self.get_cm_config("full")
        current = {r.name: r.value for r in existing}
        if self.type == "freeipa":
            self.external_auth_info_output = {
                key: value
                for key, value in current.items()
                if key in FREEIPA_EXTERNAL_CONFIGS
            }
        elif self.type == "kerberos":
            self.external_auth_info_output = {
                key: value
                for key, value in current.items()
                if key in KERBEROS_EXTERNAL_CONFIGS
            }
        else:
            self.external_auth_info_output = {
                key: value
                for key, value in current.items()
                if key
                in (set(FREEIPA_EXTERNAL_CONFIGS) | set(KERBEROS_EXTERNAL_CONFIGS))
            }


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            type=dict(
                type="str",
                required=False,
                choices=["freeipa", "kerberos"],
            ),
        ),
        supports_check_mode=False,
    )

    result = ClouderaExternalAuthInfo(module)

    output = dict(
        changed=False,
        external_auth_info=result.external_auth_info_output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
