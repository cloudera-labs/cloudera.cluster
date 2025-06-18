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
module: external_account_info
short_description: Retrieve external account details details.
description:
  - Provides details for a specific account or retrieves all external accounts configured in Cloudera Manager.
author:
  - "Ronald Suplina (@rsuplina)"
options:
  name:
    description:
      - The initial name of the account.
    type: str
    required: no
  type:
    description:
      - The type of the external account.
    type: str
    required: no
    choices:
      - AWS_ACCESS_KEY_AUTH
      - AWS_IAM_ROLES_AUTH
      - ALTUS_ACCESS_KEY_AUTH
      - ADLS_AD_SVC_PRINC_AUTH
      - BASIC_AUTH
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - cloudera.cluster.message
  - ansible.builtin.action_common_attributes
attributes:
  check_mode:
    support: full
requirements:
  - cm-client
"""

EXAMPLES = r"""
- name: Get all external accounts in Cloudera Manager
  cloudera.cluster.external_account_info:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"

- name: Get all external accounts with type "AWS_ACCESS_KEY_AUTH"
  cloudera.cluster.external_account_info:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: "AWS_ACCESS_KEY_AUTH"

- name: Get specific external account
  cloudera.cluster.external_account_info:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: "aws_test_key"
"""

RETURN = r"""
external_accounts:
    description:
        - List of one or more external accounts within the cluster.
    type: list
    elements: dict
    returned: always
    contains:
        name:
            description: Represents the initial name of the account.
            type: str
            returned: always
        display_name:
            description: A modifiable label to identify this account for user-visible purposes.
            type: str
            returned: always
        created_time:
            description: The time of creation for this account.
            type: str
            returned: always
        last_modified_time:
            description: The last modification time for this account.
            type: str
            returned: always
        type_name:
            description: The Type ID of a supported external account type.
            type: str
            returned: always
        account_configs:
            description: The configuration options for this account.
            type: list
            elements: dict
            returned: always
"""

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from cm_client.rest import ApiException
from cm_client import (
    ExternalAccountsResourceApi,
)


class ClouderaExternalAccountInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaExternalAccountInfo, self).__init__(module)

        # Set the parameters
        self.name = self.get_param("name")
        self.type = self.get_param("type")

        # Initialize the return values
        self.external_accounts = []
        self.changed = False

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        api_instance = ExternalAccountsResourceApi(self.api_client)
        account_types = [
            "AWS_ACCESS_KEY_AUTH",
            "AWS_IAM_ROLES_AUTH",
            "ALTUS_ACCESS_KEY_AUTH",
            "ADLS_AD_SVC_PRINC_AUTH",
            "BASIC_AUTH",
        ]
        try:
            if self.name:
                self.external_accounts = [
                    api_instance.read_account(self.name).to_dict()
                ]

            elif self.type:
                self.external_accounts = (
                    api_instance.read_accounts(self.type).to_dict().get("items", [])
                )

            else:

                self.external_accounts = api_instance.read_accounts(
                    type_name="AWS_ACCESS_KEY_AUTH"
                ).to_dict()["items"]
                all_accounts = []
                for account_type in account_types:
                    accounts = (
                        api_instance.read_accounts(type_name=account_type)
                        .to_dict()
                        .get("items", [])
                    )
                    all_accounts.extend(accounts)
                self.external_accounts = all_accounts

        except ApiException as e:
            if e.status == 404:
                self.cm_cluster_info = f"Account {self.name} does not exist."
                self.module.fail_json(msg=str(self.external_accounts))


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            name=dict(required=False, type="str"),
            type=dict(
                type="str",
                required=False,
                choices=[
                    "AWS_ACCESS_KEY_AUTH",
                    "AWS_IAM_ROLES_AUTH",
                    "ALTUS_ACCESS_KEY_AUTH",
                    "ADLS_AD_SVC_PRINC_AUTH",
                    "BASIC_AUTH",
                ],
            ),
        ),
        supports_check_mode=False,
    )

    result = ClouderaExternalAccountInfo(module)

    output = dict(
        changed=False,
        external_accounts=result.external_accounts,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
