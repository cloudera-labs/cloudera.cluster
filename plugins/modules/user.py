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
module: user
short_description: Create, delete or update users within Cloudera Manager
description:
  - Creates a user with specified authorization roles in Cloudera Manager, or updates roles for an existing user.
  - Supports purging roles or adding new roles to the existing list.
  - Enables the deletion of a user along with its associated roles if desired.
author:
  - "Ronald Suplina (@rsuplina)"
version_added: "4.4.0"
requirements:
  - cm_client
options:
  account_name:
    description:
      - The name of the user account to be managed.
    type: str
    required: true
  account_password:
    description:
      - The password for the account.
      - Required when creating a new account.
    type: str
    required: false
  roles:
    description:
      - A list of authentication roles associated with the account.
      - Existing roles are preserved unless C(purge) is set to True.
    type: list
    required: false
    aliases:
      - auth_roles
  purge:
    description:
      - When set to True, ensures that roles not listed in C(roles) are removed from the account.
    type: bool
    default: false
  state:
    description:
      - Controls the desired state of the account.
      - C(present) ensures the account exists with the specified parameters.
      - C(absent) deletes the account and its associated roles.
    type: str
    default: present
    choices:
      - present
      - absent
"""

EXAMPLES = r"""
- name: Create new Administrator user
  cloudera.cluster.user:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    account_name: "admin_user"
    account_password: "Password123"
    roles: ["Full Administrator"]
    state: "present"
    purge: false

- name: Add additional roles to user
  cloudera.cluster.user:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    account_name: "john"
    account_password: "Password123"
    roles: ["Configurator", "Dashboard User", "Limited Operator"]
    state: "present"

- name: Reduce permissions on user to a single role
  cloudera.cluster.user:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    account_name: "john"
    account_password: "Password123"
    roles: ["Dashboard User"]
    state: "present"
    purge: true

- name: Remove specified user
  cloudera.cluster.user:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    account_name: "john"
    roles: ["Dashboard User"]
    state: "absent"
"""

RETURN = r"""
user:
    description: Details of a single user within the cluster
    type: dict
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
from cm_client import (
    UsersResourceApi,
    ApiUser2,
    ApiAuthRoleRef,
    ApiUser2List,
    AuthRolesResourceApi,
)


class ClouderaUserInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaUserInfo, self).__init__(module)

        # Set the parameters
        self.account_name = self.get_param("account_name")
        self.account_password = self.get_param("account_password")
        self.roles = self.get_param("roles")
        self.state = self.get_param("state")
        self.purge = self.get_param("purge")

        # Initialize the return values
        self.user_output = []
        self.changed = False
        self.diff = {}

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        api_instance = UsersResourceApi(self.api_client)
        auth_role_api_instance = AuthRolesResourceApi(self.api_client)
        all_roles = auth_role_api_instance.read_auth_roles().to_dict()["items"]
        existing = []

        try:
            existing = api_instance.read_user2(self.account_name).to_dict()
        except ApiException as ex:
            if ex.status == 404:
                pass
            else:
                raise ex

        if self.state == "present":

            if existing:
                incoming_roles = [
                    role["uuid"]
                    for role in all_roles
                    if role["display_name"] in self.roles
                ]
                existing_roles = [role["uuid"] for role in existing["auth_roles"] or []]

                if self.module._diff:
                    current_roles = set(existing_roles)
                    incoming_roles_set = set(incoming_roles)
                    self.diff.update(
                        before=list(current_roles - incoming_roles_set),
                        after=list(incoming_roles_set - current_roles),
                    )
                if self.purge:
                    roles_to_add = incoming_roles
                else:
                    roles_to_add = list(set(existing_roles) | set(incoming_roles))

                if roles_to_add:
                    auth_roles = [
                        ApiAuthRoleRef(uuid=role_uuid) for role_uuid in roles_to_add
                    ]
                    self.user_output = api_instance.update_user2(
                        self.account_name,
                        body=ApiUser2(
                            name=self.account_name,
                            auth_roles=auth_roles,
                            password=self.account_password,
                        ),
                    ).to_dict()
                    self.changed = True
                else:
                    auth_roles = []
                    self.user_output = api_instance.update_user2(
                        self.account_name,
                        body=ApiUser2(
                            name=self.account_name,
                            auth_roles=auth_roles,
                            password=self.account_password,
                        ),
                    ).to_dict()
                    self.changed = True

            else:
                incoming_roles = [
                    role["uuid"]
                    for role in all_roles
                    if role["display_name"] in self.roles
                ]
                auth_roles = [
                    ApiAuthRoleRef(uuid=role_uuid) for role_uuid in incoming_roles
                ]
                api_instance.create_users2(
                    body=ApiUser2List(
                        items=[
                            ApiUser2(
                                name=self.account_name,
                                auth_roles=auth_roles,
                                password=self.account_password,
                            ),
                        ],
                    ),
                )
                self.user_output = api_instance.read_user2(self.account_name).to_dict()

                self.changed = True

        if self.state == "absent":
            if existing:
                self.user_output = api_instance.delete_user2(
                    self.account_name,
                ).to_dict()
                self.changed = True


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            account_name=dict(required=True, type="str"),
            account_password=dict(required=False, type="str"),
            roles=dict(required=False, type="list", aliases=["auth_roles"]),
            purge=dict(type="bool", default=False),
            state=dict(
                type="str",
                default="present",
                choices=["present", "absent"],
            ),
        ),
        supports_check_mode=False,
    )

    result = ClouderaUserInfo(module)

    output = dict(
        changed=False,
        user_output=result.user_output,
    )
    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
