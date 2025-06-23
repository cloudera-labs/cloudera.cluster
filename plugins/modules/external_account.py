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
module: external_account
short_description: Create, update, or delete an external module account
description:
  - Manage external accounts, including creation, updates, and deletion.
  - Supports a variety of account types such as AWS, Azure, Altus, and Basic Authentication.
  - Configure account-specific parameters, including access keys, client secrets, or basic credentials.
  - Supports I(check_mode).
author:
  - "Ronald Suplina (@rsuplina)"
version_added: "5.0.0"
options:
  name:
    description:
      - The initial name of the account.
    type: str
    required: no
  category:
    description:
      - The category of the account.
    type: str
    required: no
    choices:
      - AWS
      - ALTUS
      - AZURE
      - BASICAUTH
  state:
    description:
      - If O(state=present), the account will be created or updated.
      - If O(state=absent), the account will be deleted.
    type: str
    required: no
    default: present
    choices:
      - present
      - absent
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
  params:
    description:
      - A dictionary of parameters for the external account configuration.
      - The required parameters depend on the type of the account.
    type: dict
    required: no
    suboptions:
      aws_access_key:
        description:
          - The AWS access key for AWS_ACCESS_KEY_AUTH.
        type: str
      aws_secret_key:
        description:
          - The AWS secret key for AWS_ACCESS_KEY_AUTH.
        type: str
      access_key_id:
        description:
          - The Altus access key ID for ALTUS_ACCESS_KEY_AUTH.
        type: str
      private_key:
        description:
          - The private key for ALTUS_ACCESS_KEY_AUTH.
        type: str
      adls_tenant_id:
        description:
          - The Azure AD tenant ID for ADLS_AD_SVC_PRINC_AUTH.
        type: str
      adls_client_id:
        description:
          - The Azure AD client ID for ADLS_AD_SVC_PRINC_AUTH.
        type: str
      adls_client_key:
        description:
          - The Azure AD client secret key for ADLS_AD_SVC_PRINC_AUTH.
        type: str
      username:
        description:
          - The username for BASIC_AUTH.
        type: str
      password:
        description:
          - The password for BASIC_AUTH.
        type: str
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - cloudera.cluster.message
  - ansible.builtin.action_common_attributes
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
requirements:
  - cm-client
"""

EXAMPLES = r"""
- name: Create AWS Access key credentials
  cloudera.cluster.external_account:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: access_key_1
    state: present
    type: AWS
    category: AWS_ACCESS_KEY_AUTH
    params:
      aws_access_key: access_key1
      aws_secret_key: secret_key1

- name: Create basic authentication credentials
  cloudera.cluster.external_account:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: Jane
    state: present
    type: BASIC_AUTH
    category: BASICAUTH
    params:
      username: jane_user
      password: pass123!

- name: Update AWS Access key credentials
  cloudera.cluster.external_account:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: access_key_1
    state: present
    type: AWS
    category: AWS_ACCESS_KEY_AUTH
    params:
      aws_access_key: access_key2
      aws_secret_key: secret_key2

- name: Remove basic authentication credentials
  cloudera.cluster.external_account:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: Jane
    state: absent
"""

RETURN = r"""
external_account:
    description: Details of the external account created, updated, or retrieved.
    type: dict
    elements: complex
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

import json

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from cm_client.rest import ApiException
from cm_client import (
    ExternalAccountsResourceApi,
    ApiExternalAccount,
    ApiConfig,
    ApiConfigList,
)


class ClouderaExternalAccount(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaExternalAccount, self).__init__(module)

        # Set the parameters
        self.name = self.get_param("name")
        self.category = self.get_param("category")
        self.type = self.get_param("type")
        self.params = self.get_param("params")
        self.state = self.get_param("state")

        # Initialize the return values
        self.external_account = []
        self.changed = False

        if self.module._diff:
            self.diff = dict(before=dict(), after=dict())
            self.before = dict()
            self.after = dict()
        else:
            self.diff = dict()

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        api_instance = ExternalAccountsResourceApi(self.api_client)
        existing = []
        self.params = {
            key: value for key, value in self.params.items() if value is not None
        }
        try:
            existing = api_instance.read_account(self.name).to_dict()
        except ApiException as ex:
            if ex.status == 400:
                pass
            else:
                raise ex

        if self.state == "present":
            try:
                if existing:

                    if self.module._diff:
                        self.before.update(existing)
                        self.after.update(
                            name=self.name,
                            display_name=self.name,
                            type_name=self.type,
                            account_configs={
                                key: value for key, value in self.params.items()
                            },
                        )
                        if self.before != self.after:
                            self.diff["before"].update(self.before)
                            self.diff["after"].update(self.after)

                    if not self.module.check_mode:
                        self.external_account = api_instance.update_account(
                            body=ApiExternalAccount(
                                name=self.name,
                                display_name=self.name,
                                type_name=self.type,
                                account_configs=ApiConfigList(
                                    items=[
                                        ApiConfig(name=key, value=value)
                                        for key, value in self.params.items()
                                    ]
                                ),
                            )
                        )
                        self.changed = True
                else:
                    if self.module._diff:
                        self.diff["before"] = {}
                        self.diff["after"] = {
                            "name": self.name,
                            "display_name": self.name,
                            "type_name": self.type,
                            "account_configs": {
                                key: value for key, value in self.params.items()
                            },
                        }
                    if not self.module.check_mode:
                        self.external_account = api_instance.create_account(
                            body=ApiExternalAccount(
                                name=self.name,
                                display_name=self.name,
                                type_name=self.type,
                                account_configs=ApiConfigList(
                                    items=[
                                        ApiConfig(name=key, value=value)
                                        for key, value in self.params.items()
                                    ]
                                ),
                            )
                        )
                        self.changed = True

            except ApiException as ex:
                if ex.status == 400:
                    self.module.fail_json(msg=json.loads(ex.body)["message"])
                else:
                    raise ex

        if self.state == "absent":
            if not self.module.check_mode:
                if existing:
                    self.external_account = api_instance.delete_account(self.name)
                    self.changed = True


def main():

    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            name=dict(required=True, type="str"),
            category=dict(
                type="str",
                required=False,
                choices=["AWS", "ALTUS", "AZURE", "BASICAUTH"],
            ),
            state=dict(
                type="str",
                default="present",
                choices=["present", "absent"],
            ),
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
            params=dict(
                type="dict",
                default={},
                options=dict(
                    # AWS params
                    aws_access_key=dict(type="str"),
                    aws_secret_key=dict(type="str"),
                    # ALTUS params
                    access_key_id=dict(type="str"),
                    private_key=dict(type="str"),
                    # AZURE params
                    adls_tenant_id=dict(type="str"),
                    adls_client_id=dict(type="str"),
                    adls_client_key=dict(type="str"),
                    # BASIC auth params
                    username=dict(type="str"),
                    password=dict(type="str"),
                ),
            ),
            required_if={
                "AWS_ACCESS_KEY_AUTH": [
                    "params.aws_access_key",
                    "params.aws_secret_key",
                ],
                "ADLS_AD_SVC_PRINC_AUTH": [
                    "params.adls_client_id",
                    "params.adls_client_id",
                    "params.adls_tenant_id",
                ],
                "ALTUS_ACCESS_KEY_AUTH": [
                    "params.access_key_id",
                    "params.private_key",
                ],
                "BASIC_AUTH": [
                    "params.username",
                    "params.password",
                ],
            },
        ),
        supports_check_mode=True,
    )

    result = ClouderaExternalAccount(module)

    output = dict(
        changed=result.changed,
        external_account=result.external_account,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
