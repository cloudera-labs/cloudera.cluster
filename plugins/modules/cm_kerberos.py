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
module: cm_kerberos
short_description: Manage and configure Kerberos Authentication for CDP
description:
  - Manages Kerberos authentication and configuration in Cloudera Manager.
  - Imports the KDC Account Manager credentials needed by Cloudera Manager to create kerberos principals.
author:
  - "Jim Enright (@jimright)"
requirements:
  - cm_client
options:
  state:
    description:
      - The declarative state of Kerberos configuration.
    type: str
    required: false
    default: present
    choices:
      - present
      - absent
  force:
    description:
      - Forces an attempt to generate the KDC Account Manager credentials even if Kerberos is already determined to be enabled.
      - Applicable only when O(state) is V(present).
  krb_enc_types:
    description:
      - Kerberos Encryption Types supported by the KDC to set in Cloudera Manager configuration.
    type: list
    elements: str
    required: false
  security_realm:
    description:
      - Kerberos Security Realm to set in Cloudera Manager configuration
      - Changing this variable removes existing credentials and keytabs from Cloudera Manager and will attempt to re-generate these credentials.
    type: str
    required: false
  kdc_type:
    description:
      - Type of KDC Kerberos key distribution center (KDC) used for authentication.
    type: str
    required: false
    choices:
      - 'MIT KDC'
      - 'Active Directory'
      - 'Red Hat IPA'
  kdc_admin_host:
    description:
      - KDC Admin Server Host
      - Port number is optional and can be provided as V(hostname:port)
    type: str
    required: false
  kdc_host:
    description:
      - KDC Server Host
      - Port number is optional and can be provided as V(hostname:port)
    type: str
    required: false
  krb_auth_enable:
    description:
      - Enable SPNEGO/Kerberos Authentication for the Admin Console and API
    type: bool
    required: false
  ad_account_prefix:
    description:
      - Prefix used in names while creating accounts in Active Directory.
      - The prefix can be up to 15 characters long and can be set to identify accounts used for authentication by CDH processes.
      - Used only if O(kdc_type='Active Directory').
    type: str
    required: false
  ad_kdc_domain:
    description:
      - Active Directory suffix where all the accounts used by CDH daemons will be created.
      - Used only if O(kdc_type='Active Directory').
    type: str
    required: false
  ad_delete_on_regenerate:
    description:
      - Active Directory Delete Accounts on Credential Regeneration.
      - Set this option to V(true) if regeneration of credentials should automatically delete the associated Active Directory accounts.
      - Used only if O(kdc_type='Active Directory').
    type: bool
    required: false
  ad_set_encryption_types:
    description:
      - Set this V(true) if creation of Active Directory accounts should automatically turn on the associated encryption types represented by the msDS-EncryptionTypes field.
      - Used only if O(kdc_type='Active Directory').
    type: bool
    required: false
  kdc_account_creation_host_override:
    description:
      - Active Directory Domain Controller host override.
      - This parameter should be used when multiple Active Directory Domain Controllers are behind a load-balancer.
      - This parameter should be set with the address of one of them AD Domain Controller.
      - This setting is used only while creating accounts. CDH services use the value entered in the O(kdc_host) while authenticating.
      - Only applicable if O(kdc_type='Active Directory')
    type: str
    required: false
  gen_keytab_script:
    description:
      - Custom Kerberos Keytab Retrieval Script.
      - Specify the path to a custom script, or executable, to retrieve a Kerberos keytab.
      - "The target script should accept two arguments: a destination path for the resulting keytab and the full principal name of the owner of the keytab."
    type: str
    required: false
  kdc_admin_user:
    description:
      - Username of the Kerberos Account Manager to create kerberos principals.
      - The Kerberos realm must be specified in the principal name, for example V(username@CLDR.EXAMPLE).
    type: str
    required: false
  kdc_admin_password:
    description:
      - Password of the Kerberos Account Manager to create kerberos principals.
    type: str
    required: false
extends_documentation_fragment:
  - cloudera.cluster.cm_endpoint
  - cloudera.cluster.message
notes:
  - Using O(cloudera.cluster.cm_config#module:purge=yes) will remove the Cloudera Manager configurations set by this module.
  - Requires C(cm_client).
seealso:
  - module: cloudera.cluster.cm_config
"""

EXAMPLES = r"""
- name: Enable Kerberos
  cloudera.cluster.cm_kerberos:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    security_realm: "CLDR.INTERNAL"
    kdc_type: "Red Hat IPA"
    krb_enc_types: "aes256-cts aes128-cts rc4-hmac"
    kdc_admin_host: "freeipa.cldr.internal"
    kdc_host: "freeipa.cldr.internal"
    kdc_admin_user: "admin@CLDR.INTERNAL"
    kdc_admin_password: "kdcExamplePass"
    state: present

- name: Disable Kerberos
  cloudera.cluster.cm_kerberos:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    state: absent
"""

RETURN = r"""
cm_config:
  description:
    - Cloudera Manager Server configurations with Kerberos settings where available.
  type: list
  elements: dict
  returned: always
  contains:
    name:
      description:
        - The canonical name that identifies this configuration parameter.
      type: str
      returned: always
    value:
      description:
        - The user-defined value.
        - When absent, the default value (if any) will be used.
        - Can also be absent, when enumerating allowed configs.
      type: str
      returned: when supported
    required:
      description:
        - Whether this configuration is required for the object.
        - If any required configuration is not set, operations on the object may not work.
      type: bool
      returned: when supported
    default:
      description:
        - The default value.
      type: str
      returned: when supported
    display_name:
      description:
        - A user-friendly name of the parameters, as would have been shown in the web UI.
      type: str
      returned: when supported
    description:
      description:
        - A textual description of the parameter.
      type: str
      returned: when supported
    related_name:
      description:
        - If applicable, contains the related configuration variable used by the source project.
      type: str
      returned: when supported
    sensitive:
      description:
        - Whether this configuration is sensitive, i.e. contains information such as passwords.
        - This parameter might affect how the value of this configuration might be shared by the caller.
      type: bool
      returned: when supported
    validate_state:
      description:
        - State of the configuration parameter after validation.
        - For example, C(OK), C(WARNING), and C(ERROR).
      type: str
      returned: when supported
    validation_message:
      description:
        - A message explaining the parameter's validation state.
      type: str
      returned: when supported
    validation_warnings_suppressed:
      description:
        - Whether validation warnings associated with this parameter are suppressed.
        - In general, suppressed validation warnings are hidden in the Cloudera Manager UI.
        - Configurations that do not produce warnings will not contain this field.
      type: bool
      returned: when supported
"""

import re

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerMutableModule,
    resolve_parameter_changeset,
)

from cm_client import (
    ClouderaManagerResourceApi,
    ApiConfigList,
    ApiConfig,
)


class ClouderaManagerKerberos(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClouderaManagerKerberos, self).__init__(module)

        # Set the parameters
        self.state = self.get_param("state")
        self.force = self.get_param("force")
        self.krb_enc_types = self.get_param("krb_enc_types")
        self.security_realm = self.get_param("security_realm")
        self.kdc_type = self.get_param("kdc_type")
        self.kdc_admin_host = self.get_param("kdc_admin_host")
        self.kdc_host = self.get_param("kdc_host")
        self.krb_auth_enable = self.get_param("krb_auth_enable")
        self.ad_account_prefix = self.get_param("ad_account_prefix")
        self.ad_kdc_domain = self.get_param("ad_kdc_domain")
        self.ad_delete_on_regenerate = self.get_param("ad_delete_on_regenerate")
        self.ad_set_encryption_types = self.get_param("ad_set_encryption_types")
        self.kdc_account_creation_host_override = self.get_param(
            "kdc_account_creation_host_override"
        )
        self.gen_keytab_script = self.get_param("gen_keytab_script")
        self.kdc_admin_user = self.get_param("kdc_admin_user")
        self.kdc_admin_password = self.get_param("kdc_admin_password")

        # Initialize the return values
        self.output = {}
        self.changed = False
        self.diff = {}

        self.delay = (
            15  # Sleep time between wait for import_admin_credentials cmd to complete
        )
        # List of known acceptable errors in import_admin_credentials cmd
        self.creds_known_errors = [r"ERROR: user with name.*already exists"]

        # Execute the logic
        self.process()

    @ClouderaManagerMutableModule.handle_process
    def process(self):

        # Check parameters that should only specified with skdc_type == Active Directory
        if self.kdc_type != "Active Directory" and (
            self.ad_account_prefix
            or self.ad_kdc_domain
            or self.ad_delete_on_regenerate
            or self.ad_set_encryption_types
        ):
            self.module.fail_json(
                msg="Parameters 'ad_account_prefix', 'ad_kdc_domain', 'ad_delete_on_regenerate' or 'ad_set_encryption_types' can only be used with 'kdc_type = Active Directory'"
            )

        # Convert encryption types to space separated string
        if self.krb_enc_types:
            self.krb_enc_types = " ".join(self.krb_enc_types)

        # create an instance of the API class
        cm_api_instance = ClouderaManagerResourceApi(self.api_client)

        # Check current CM configuration
        existing = self.get_cm_config(scope="full")
        current = {r.name: r.value for r in existing}

        # State present
        if self.state == "present":

            # Determine CM configuration changes for Kerberos
            incoming = {
                key.upper(): getattr(self, key)
                for key in [
                    "krb_enc_types",
                    "security_realm",
                    "kdc_type",
                    "kdc_admin_host",
                    "kdc_host",
                    "krb_auth_enable",
                    "ad_account_prefix",
                    "ad_kdc_domain",
                    "ad_delete_on_regenerate",
                    "ad_set_encryption_types",
                    "kdc_account_creation_host_override",
                    "gen_keytab_script",
                ]
            }
            change_set = resolve_parameter_changeset(current, incoming)

            if change_set:
                self.changed = True

                if self.module._diff:
                    self.diff = dict(
                        before={k: current[k] for k in change_set.keys()},
                        after=change_set,
                    )

                if not self.module.check_mode:
                    body = ApiConfigList(
                        items=[
                            ApiConfig(name=k, value=v) for k, v in change_set.items()
                        ]
                    )
                    cm_api_instance.update_config(message=self.message, body=body).items

            # Generate Kerberos credentials
            # Check and create Kerberos credentials if required
            if self.kdc_admin_user and self.kdc_admin_password:
                # Retrieve CM Kerberos information
                krb_info = cm_api_instance.get_kerberos_info().to_dict()

                if krb_info.get("kerberized") == False or self.force:

                    # Generate credentials
                    if not self.module.check_mode:
                        cmd = cm_api_instance.import_admin_credentials(
                            username=self.kdc_admin_user,
                            password=self.kdc_admin_password,
                        )
                        creds_cmd_result = next(
                            iter(
                                self.wait_for_command_state(
                                    command_id=cmd.id, polling_interval=self.delay
                                )
                            ),
                            None,
                        )

                        if creds_cmd_result.success:
                            self.changed = True
                        else:
                            # Check for known, acceptable errors in import_admin_credentials
                            if not any(
                                re.search(item, creds_cmd_result.result_message)
                                for item in self.creds_known_errors
                            ):
                                self.module.fail_json(
                                    msg="Error during Import KDC Account Manager Credentials command",
                                    error=creds_cmd_result.result_message,
                                )

            # Retrieve cm_config again after enabling Kerberos
            self.output.update(cm_config=[r.to_dict() for r in self.get_cm_config()])

        elif self.state == "absent":

            # Remove Kerberos credentials
            if not self.module.check_mode:
                krb_info = cm_api_instance.get_kerberos_info().to_dict()
                if krb_info.get("kerberized") == True:
                    cm_api_instance.delete_credentials_command()

            # Reset CM configurations
            reset_params = dict(
                krb_enc_types="aes256-cts",
                security_realm="HADOOP.COM",
                kdc_type="MIT KDC",
                kdc_admin_host="",
                kdc_host="",
                krb_auth_enable=False,
                ad_account_prefix="",
                ad_kdc_domain="ou=hadoop,DC=hadoop,DC=com",
                ad_delete_on_regenerate=False,
                ad_set_encryption_types=False,
                kdc_account_creation_host_override="",
                gen_keytab_script="",
            )
            # NOTE: Change set is always > 0
            change_set = resolve_parameter_changeset(
                current, {k.upper(): v for k, v in reset_params.items()}
            )

            if change_set:
                self.changed = True

                if self.module._diff:
                    self.diff = dict(
                        before={k: current[k] for k in reset_params.keys()},
                        after=reset_params,
                    )

                if not self.module.check_mode:
                    body = ApiConfigList(
                        items=[
                            ApiConfig(name=k, value=v) for k, v in reset_params.items()
                        ]
                    )
                    cm_api_instance.update_config(body=body).items

                # Set output
                # Retrieve cm_config again after enabling Kerberos
                self.output.update(
                    cm_config=[r.to_dict() for r in self.get_cm_config()]
                )


def main():

    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            krb_enc_types=dict(required=False, type="list"),
            security_realm=dict(required=False, type="str"),
            kdc_type=dict(
                type="str",
                choices=["MIT KDC", "Active Directory", "Red Hat IPA"],
            ),
            kdc_admin_host=dict(required=False, type="str"),
            kdc_host=dict(required=False, type="str"),
            krb_auth_enable=dict(required=False, type="bool"),
            ad_account_prefix=dict(required=False, type="str"),
            ad_kdc_domain=dict(required=False, type="str"),
            ad_delete_on_regenerate=dict(required=False, type="bool"),
            ad_set_encryption_types=dict(required=False, type="bool"),
            kdc_account_creation_host_override=dict(required=False, type="str"),
            gen_keytab_script=dict(required=False, type="str"),
            kdc_admin_user=dict(required=False, type="str"),
            kdc_admin_password=dict(required=False, type="str", no_log=True),
            state=dict(type="str", default="present", choices=["present", "absent"]),
            force=dict(required=False, type="bool", default=False),
        ),
        supports_check_mode=True,
    )

    result = ClouderaManagerKerberos(module)

    output = dict(
        changed=result.changed,
        **result.output,
    )
    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
