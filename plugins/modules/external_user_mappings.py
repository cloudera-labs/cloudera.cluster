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

from cm_client import (
    ExternalUserMappingsResourceApi,
    ApiExternalUserMapping,
    ApiAuthRoleRef,
)

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: external_user_mappings
short_description: Create, update, or delete external user mappings
description:
  - Configure details of a specific external user mapping.
  - Create a new external user mapping.
  - Update an existing external user mapping.
  - Delete a external user mapping.
  - The module supports C(check_mode).
author:
  - "Ronald Suplina (@rsuplina)"
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
  type:
    description:
      - The type of the external mapping.
    type: str
    required: no
  auth_roles:
    description:
      - A list of auth roles that the external user mapping will include.
    type: list
    required: no
  state:
    description:
      - If I(state=present), the external user mapping will be created or updated.
      - If I(state=absent), the external user mapping will be updated or deleted.
    type: str
    required: no
    default: present
    choices:
      - present
      - absent
  purge:
    description:
      - Flag for whether the declared auth roles should append or overwrite any existing auth roles.
    type: bool
    default: False
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
"""

EXAMPLES = r"""
---
- name: Create external user mapping with admin permissions
  cloudera.cluster.external_user_mappings:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: "admin_user"
    state: "present"
    type: "LDAP"
    auth_roles: ["ROLE_CLUSTER_ADMIN"]

- name: Add additional permissions to external user mapping
  cloudera.cluster.external_user_mappings:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: "basic_user"
    state: "present"
    type: "LDAP"
    auth_roles: ["ROLE_DASHBOARD_USER","ROLE_USER","ROLE_CLUSTER_CREATOR"]
    
- name: Replace current permissions in external user mapping
  cloudera.cluster.external_user_mappings:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: "basic_user"
    state: "present"
    purge: "True"
    type: "LDAP"
    auth_roles: ["ROLE_DASHBOARD_USER","ROLE_USER"]

- name: Remove external user mapping
  cloudera.cluster.external_user_mappings:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: "default_user"
    state: "absent"
    type: "LDAP"

- name: Remove permissions from external user mapping
  cloudera.cluster.external_user_mappings:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: "default_user"
    state: "absent"
    type: "LDAP"
    auth_roles: ["ROLE_DASHBOARD_USER","ROLE_USER"]
"""

RETURN = r"""
---
external_user_mappings:
  description:
    - A dictionary containing details of external user mapping.
  type: dict
  elements: complex
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


class ClouderaExternalUserMappingsInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaExternalUserMappingsInfo, self).__init__(module)

        # Set the parameters
        self.name = self.get_param("name")
        self.uuid = self.get_param("uuid")
        self.state = self.get_param("state")
        self.type = self.get_param("type")
        self.purge = self.get_param("purge")
        self.auth_roles = self.get_param("auth_roles")

        # Initialize the return value
        self.host_template = []
        self.external_user_mappings_output = []
        self.changed = False
        self.diff = {}

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        api_instance = ExternalUserMappingsResourceApi(self.api_client)
        existing = []

        if self.name:
            all_external_user_mappings = api_instance.read_external_user_mappings()
            for mapping in all_external_user_mappings.items:
                if self.name == mapping.name:
                    existing = api_instance.read_external_user_mapping(
                        uuid=mapping.uuid
                    ).to_dict()
                    break
        if self.uuid:
            existing = api_instance.read_external_user_mapping(uuid=self.uuid).to_dict()
        if self.state == "present":
            if existing:
                existing_auth_roles = [
                    auth_role["name"] for auth_role in existing["auth_roles"]
                ]
                incoming_auth_roles = set(self.auth_roles)
                if existing_auth_roles != incoming_auth_roles:
                    if self.module._diff:
                        self.diff.update(
                            before=list(existing_auth_roles - incoming_auth_roles),
                            after=list(incoming_auth_roles - existing_auth_roles),
                        )
                    if self.purge:
                        target_auth_roles = incoming_auth_roles
                    else:
                        existing_auth_roles = set(existing_auth_roles)
                        new_auth_roles = incoming_auth_roles - existing_auth_roles
                        target_auth_roles = existing_auth_roles.union(new_auth_roles)

                    auth_roles = [
                        ApiAuthRoleRef(name=role) for role in target_auth_roles
                    ]
                    update_existing_auth_roles = ApiExternalUserMapping(
                        name=self.name,
                        uuid=mapping.uuid,
                        type=self.type,
                        auth_roles=auth_roles,
                    )
                    if not self.module.check_mode:
                        self.external_user_mappings_output = (
                            api_instance.update_external_user_mapping(
                                uuid=mapping.uuid, body=update_existing_auth_roles
                            )
                        ).to_dict()
                        self.changed = True
            else:
                auth_roles = [ApiAuthRoleRef(name=role) for role in self.auth_roles]
                external_user_mappings_body = ApiExternalUserMapping(
                    name=self.name,
                    uuid=mapping.uuid,
                    type=self.type,
                    auth_roles=auth_roles,
                )

                if not self.module.check_mode:
                    self.external_user_mappings_output = (
                        api_instance.create_external_user_mappings(
                            body={"items": [external_user_mappings_body]}
                        )
                    ).to_dict()["items"]
                    self.changed = True

        if self.state == "absent":
            if existing:
                if self.auth_roles:
                    existing_auth_roles = set(
                        auth_role["name"] for auth_role in existing["auth_roles"]
                    )
                    incoming_auth_roles = set(self.auth_roles)

                    roles_to_delete = existing_auth_roles.intersection(
                        incoming_auth_roles
                    )
                    if self.module._diff:
                        self.diff.update(
                            before=list(roles_to_delete),
                            after=[],
                        )
                    if roles_to_delete:
                        remaining_roles = existing_auth_roles - roles_to_delete
                        auth_roles = [
                            ApiAuthRoleRef(name=role) for role in remaining_roles
                        ]
                        update_existing_auth_roles = ApiExternalUserMapping(
                            name=self.name,
                            uuid=mapping.uuid,
                            type=self.type,
                            auth_roles=auth_roles,
                        )
                        if not self.module.check_mode:
                            self.external_user_mappings_output = (
                                api_instance.update_external_user_mapping(
                                    uuid=mapping.uuid, body=update_existing_auth_roles
                                )
                            ).to_dict()
                            self.changed = True
                else:
                    if not self.module.check_mode:
                        self.external_user_mappings_output = (
                            api_instance.delete_external_user_mapping(uuid=mapping.uuid)
                        ).to_dict()
                        self.changed = True


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            name=dict(required=False, type="str"),
            uuid=dict(required=False, type="str"),
            type=dict(required=False, type="str"),
            purge=dict(required=False, type="bool", default=False),
            auth_roles=dict(required=False, type="list"),
            state=dict(
                type="str",
                default="present",
                choices=["present", "absent"],
            ),
        ),
        supports_check_mode=True,
    )

    result = ClouderaExternalUserMappingsInfo(module)

    output = dict(
        changed=result.changed,
        external_user_mappings_output=result.external_user_mappings_output,
    )
    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
