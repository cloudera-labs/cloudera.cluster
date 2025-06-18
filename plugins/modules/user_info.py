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
module: user_info
short_description: Retrieve user details and associated authentication roles.
description:
  - Provides details for a specific user or retrieves all users configured in Cloudera Manager.
  - Includes information about authentication roles associated with each user.
author:
  - "Ronald Suplina (@rsuplina)"
requirements:
  - cm_client
options:
  account_name:
    description:
      - The name of the user account to be managed.
    type: str
    required: false
"""

EXAMPLES = r"""
- name: Get list of all users in Cloudera Manager
  cloudera.cluster.user_info:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"

- name: Get details for specific user
  cloudera.cluster.user_info:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    account_name: "john"
"""

RETURN = r"""
users:
    description:
      - Retrieve details of single user or all users within the Cloudera Manager
    type: list
    elements: dict
    returned: always
    contains:
        name:
            description: The username, which is unique within a Cloudera Manager installation.
            type: str
            returned: always
        auth_roles:
            description: Cloudera Manager authorization roles assigned to the user.
            type: list
            returned: optional
"""

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from cm_client.rest import ApiException
from cm_client import UsersResourceApi


class ClouderaUserInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaUserInfo, self).__init__(module)

        # Set the parameters

        self.account_name = self.get_param("account_name")

        # Initialize the return values
        self.user_info_output = []
        self.changed = False

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        api_instance = UsersResourceApi(self.api_client)

        try:
            if self.account_name:
                self.user_info_output = [
                    api_instance.read_user2(self.account_name).to_dict()
                ]
            else:
                self.user_info_output = api_instance.read_users2().to_dict()["items"]

        except ApiException as e:
            if e.status == 404:
                pass
            else:
                raise e


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            account_name=dict(required=False, type="str"),
        ),
        supports_check_mode=False,
    )

    result = ClouderaUserInfo(module)

    output = dict(
        changed=False,
        user_info_output=result.user_info_output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
