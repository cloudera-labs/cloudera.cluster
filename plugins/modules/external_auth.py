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
    resolve_parameter_updates,
)

from cm_client import ApiConfigList, ApiConfig, ClouderaManagerResourceApi


DOCUMENTATION = r"""
---
module: external_auth
short_description: Configure external authorizations configurations.
description:
  - Enables the configuration of external authentication systems(FreeIPA and Kerberos).
author:
  - "Ronald Suplina (@rsuplina)"
options:
  type:
    description:
      - The type of the external configurations to configure.
    type: str
    required: no
    choices:
      - freeipa
      - kerberos
  params:
    description:
      - A dictionary of parameters for the external configurations.
      - The required parameters depend on the type of the configuration.
    type: dict
    required: no
    suboptions:
      ldap_type:
        description:
          - Type of LDAP server.
        type: str
        required: no
      auth_backend_order:
        description:
          - Order of authentication backends.
        type: str
        required: no
      ldap_bind_dn:
        description:
          - Distinguished Name (DN) for binding to LDAP.
        type: str
        required: no
      ldap_bind_pw:
        description:
          - Password for LDAP binding.
        type: str
        required: no
      ldap_url:
        description:
          - URL of the LDAP server.
        type: str
        required: no
      ldap_user_search_base:
        description:
          - Base DN for user searches in LDAP.
        type: str
        required: no
      ldap_group_search_base:
        description:
          - Base DN for group searches in LDAP.
        type: str
        required: no
      ldap_group_search_filter:
        description:
          - Filter for group searches in LDAP.
        type: str
        required: no
      ldap_user_search_filter:
        description:
          - Filter for user searches in LDAP.
        type: str
        required: no
      krb_enc_types:
        description:
          - Types of Kerberos encryption.
        type: str
        required: no
      security_realm:
        description:
          - Security realm for Kerberos authentication.
        type: str
        required: no
      kdc_admin_host:
        description:
          - Host of the Kerberos KDC administrative service.
        type: str
        required: no
      kdc_host:
        description:
          - Host of the Kerberos KDC.
        type: str
        required: no
      kdc_type:
        description:
          - Type of Kerberos KDC (e.g., Red Hat IPA).
        type: str
        required: no
requirements:
  - cm_client
"""

EXAMPLES = r"""
---
- name: Configure FreeIPA external authorization
  cloudera.cluster.external_auth:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: "freeipa"
    params:
      ldap_type: "LDAP",
      auth_backend_order: "LDAP_THEN_DB",
      ldap_bind_dn: "uid=admin,cn=users,cn=accounts,dc=workshop,dc=com",
      ldap_bind_pw: "Password1",
      ldap_url: "ldaps://freeipa.1.1.1.1.com",
      ldap_user_search_base: "cn=users,cn=accounts,dc=workshop,dc=com",
      ldap_group_search_base: "cn=groups,cn=accounts,dc=workshop,dc=com",
      ldap_group_search_filter: "(member={0})",
      ldap_user_search_filter: "(uid={0})",

- name: Configure Kerberos external authorization
  cloudera.cluster.external_auth:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    type: "kerberos"
    params:
      KRB_ENC_TYPES: "aes256-cts rc4-hmac",
      SECURITY_REALM: "workshop.com",
      KDC_ADMIN_HOST: "freeipa.1.1.1.1.com",
      KDC_HOST: "freeipa.1.1.1.1.com",
      KDC_TYPE:  "Red Hat IPA",

"""

RETURN = r"""
---
external_auth:
    description: A dictionary containing external authentication configuration details. 
    type: dict
    returned: always

"""


class ClouderaExternalAuth(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaExternalAuth, self).__init__(module)

        # Initialize the return values
        self.params = self.get_param("params")
        self.state = self.get_param("state")
        self.purge = self.get_param("purge")
        self.type = self.get_param("type")

        # Initialize the return values
        self.external_auth_output = []
        self.changed = False
        self.diff = {}

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        existing = self.get_cm_config("full")
        current = {r.name: r.value for r in existing}
        incoming = {k.upper(): v for k, v in self.params.items()}

        change_set = resolve_parameter_updates(current, incoming, self.purge)

        if change_set:
            self.changed = True

            if self.module._diff:
                self.diff = dict(
                    before={k: current[k] for k in change_set.keys()},
                    after=change_set,
                )

            if not self.module.check_mode:
                body = ApiConfigList(
                    items=[ApiConfig(name=k, value=v) for k, v in change_set.items()]
                )
                self.config = [
                    p.to_dict()
                    for p in ClouderaManagerResourceApi(self.api_client)
                    .update_config(body=body)
                    .items
                ]


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            params=dict(required=False, type="dict", default={}),
            purge=dict(type="bool", default=False),
            state=dict(
                type="str",
                default="present",
                choices=["present", "absent"],
            ),
            type=dict(
                type="str",
                required=False,
                choices=["freeipa", "kerberos"],
            ),
        ),
        supports_check_mode=False,
    )

    result = ClouderaExternalAuth(module)

    output = dict(
        changed=False,
        external_auth=result.external_auth_output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
