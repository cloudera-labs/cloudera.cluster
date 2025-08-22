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
module: external_user_mappings_info
short_description: Retrieve details of external user mappings
description:
  - Retrieve details of a specific or all external user mappings within the Cloudera Manager.
author:
  - "Ronald Suplina (@rsuplina)"
version_added: "5.0.0"
requirements:
  - cm_client
options:
  name:
    description:
      - The name of the external mapping.
    type: str
    required: no
  uuid:
    description:
      - The uuid of the external mapping.
    type: str
    required: no
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
"""

EXAMPLES = r"""
- name: Retrieve the defailts about a specific user mapping
  cloudera.cluster.external_user_mappings_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: "test_mapping"

- name: Retrieve the defailts about a specific user mapping with uuid parameter
  cloudera.cluster.external_user_mappings_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    uuid: "1111aa-1111-111a-111a-11111111"

- name: Retrieve the details about all user mappings
  cloudera.cluster.external_user_mappings_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
"""

RETURN = r"""
external_user_mappings_info:
  description:
    - List of external user mappings within the cloudera manager.
  type: list
  elements: dict
  returned: always
  contains:
    name:
      description:
        - The name of the external mapping.
      type: str
      returned: always
    type:
      description:
        - The type of the external mapping.
      type: str
      returned: always
    uuid:
      description:
        - The UUID of the external mapping.
      type: str
      returned: always
    auth_roles:
      description:
        - The list of auth roles associated with external user mapping.
      type: list
      returned: always
"""

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)

from cm_client import (
    ExternalUserMappingsResourceApi,
)
from cm_client.rest import ApiException


class ClouderaExternalUserMappingsInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaExternalUserMappingsInfo, self).__init__(module)

        # Set the parameters
        self.name = self.get_param("name")
        self.uuid = self.get_param("uuid")

        # Initialize the return value
        self.external_user_mappings_info_output = []
        self.changed = False

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        api_instance = ExternalUserMappingsResourceApi(self.api_client)
        try:
            if self.name:
                external_user_mappings = api_instance.read_external_user_mappings()
                for mapping in external_user_mappings.items:
                    if self.name == mapping.name:
                        self.external_user_mappings_info_output = [
                            api_instance.read_external_user_mapping(
                                uuid=mapping.uuid,
                            ).to_dict(),
                        ]
            elif self.uuid:
                self.external_user_mappings_info_output = [
                    api_instance.read_external_user_mapping(uuid=self.uuid).to_dict(),
                ]
            else:
                self.external_user_mappings_info_output = (
                    api_instance.read_external_user_mappings().to_dict()["items"]
                )
        except ApiException as ex:
            if ex.status != 400:
                raise ex


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            name=dict(required=False, type="str"),
            uuid=dict(required=False, type="str"),
        ),
        supports_check_mode=True,
        mutually_exclusive=[
            ["name", "uuid"],
        ],
    )

    result = ClouderaExternalUserMappingsInfo(module)

    output = dict(
        changed=result.changed,
        external_user_mappings_info_output=result.external_user_mappings_info_output,
    )
    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
