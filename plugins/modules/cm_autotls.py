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
module: cm_autotls
short_description: Manage and configure Auto-TLS and Cloudera Manager CA
description:
  - Enables and configures Auto-TLS and Cloudera Manager as a CA.
  - Disabling of Auto-TLS is also supported.
  - Note that disabling Auto-TLS does not remove the TLS resources (keys, truststores, etc.) created during the enable process.
author:
  - "Jim Enright (@jimright)"
requirements:
  - cm_client
options:
  state:
    description:
      - The declarative state of Auto-TLS.
      - Disabling Auto-TLS does not remove the TLS resources (keys, truststores, etc.) created during the enable process.
    type: str
    required: false
    default: present
    choices:
      - present
      - absent
  force:
    description:
      - Forces enabling Auto-TLS even if it is already determined to be enabled.
      - Applicable only when O(state) is V(true).
    type: bool
    required: false
    default: false
  custom_ca:
    description:
      - Whether to generate an internal CMCA V(false) or use user-provided certificates V(true).
      - When V(true), the following parameters must be given - O(cm_host_cert), O(cm_host_key), O(ca_cert), O(keystore_passwd) and O(truststore_passwd).
    type: bool
    required: false
    default: false
  interpret_as_filenames:
    description:
      - Whether specific parameters are interpreted as filenames local to the Cloudera Manager host.
      - When V(true), the following parameter are filenames - O(cm_host_cert), O(cm_host_key), O(ca_cert), O(keystore_passwd), O(truststore_passwd), O(trusted_ca_certs), O(host_certs.host_cert) and O(host_certs.host_key).
    type: bool
    required: false
    default: true
  configure_all_services:
    description:
      - Whether to configure all existing services to use Auto-TLS.
      - If V(false), only MGMT services will be configured to use Auto-TLS.
      - All future services will be configured to use Auto-TLS regardless of this setting.
    type: bool
    required: false
    default: true
  connection_ssh_port:
    description:
      - SSH port to connect to each host.
    type: int
    required: false
  connection_user_name:
    description:
      - The username used to authenticate with the hosts.
      - Root access to your hosts is required to install Cloudera packages.
      - The installer will connect to your hosts via SSH and log in either directly as root or as another user with password-less sudo privileges to become root.
    type: str
  connection_password:
    description:
      - The password used to authenticate with the hosts.
      - Specify either this or a O(connection_password_private_key).
    type: str
  connection_private_key:
    description:
      - The private key to authenticate with the hosts.
      - Specify either this or a O(connection_password).
      - The private key, if specified, needs to be a standard PEM-encoded key as a single string, with all line breaks replaced with the line-feed control character I('\n').
    type: str
  connection_passphrase:
    description:
      - The passphrase associated with the private key used to authenticate with the hosts.
    type: str
  location:
    description:
      - The location on disk to store the CMCA directory.
      - If there is already a CMCA created there, it will be backed up, and a new one will be created in its place.
    type: str
  cm_host_cert:
    description:
      - The certificate for the CM host in PEM format.
      - Required and only used if O(custom_ca) is V(True).
    type: str
  cm_host_key:
    description:
      - The private key for the CM host in PEM format.
      - Required and only used if O(custom_ca) is V(True).
    type: str
  ca_cert:
    description:
      - The certificate for the user-provided certificate authority in PEM format.
      - Required and only used if O(custom_ca) is V(True).
    type: str
  keystore_passwd:
    description:
      - The password used for all Auto-TLS keystores.
      - Required and only used if O(custom_ca) is V(True).
    type: str
  truststore_passwd:
    description:
      - The password used for all Auto-TLS truststores.
      - Required and only used if O(custom_ca) is V(True).
    type: str
  trusted_ca_certs:
    description:
      - A list of CA certificates that will be imported into the Auto-TLS truststore and distributed to all hosts.
    type: str
  host_certs:
    description:
      - A list of cert objects for each host.
      - This associates a hostname with the corresponding certificate and private key.
      - Only used if O(custom_ca) is V(True).
    type: list
    elements: dict
    suboptions:
      hostname:
        description:
          - The FQDN of a host in the deployment.
        type: str
      certificate:
        description:
          - The certificate for this host in PEM format.
        type: str
      key:
        description:
          - The private key for this host in PEM format.
        type: str
extends_documentation_fragment:
  - ansible.builtin.action_common_attributes
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  platform:
    platforms: all
notes:
  - Using the C(cm_config) with O(purge=yes) will remove the Cloudera Manager configurations set by this module.
  - Requires C(cm_client).
seealso:
  - module: cloudera.cluster.cm_config
"""

EXAMPLES = r"""
---
- name: Enable Auto-TLS
  cloudera.cluster.cm_autotls:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    state: present
    connection_user_name: clouduser
    connection_private_key: "-----BEGIN RSA PRIVATE KEY-----\n[base-64 encoded key]\n-----END RSA PRIVATE KEY-----"

- name: Disable Auto-TLS
  cloudera.cluster.cm_autotls:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    state: absent
"""

RETURN = r"""
cm_config:
  description:
    - Cloudera Manager Server configurations with Auto-TLS settings where available.
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

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from cm_client import (
    ClouderaManagerResourceApi,
    ApiGenerateCmcaArguments,
    ApiConfigList,
    ApiConfig,
)


class ClouderaManagerAutoTLS(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaManagerAutoTLS, self).__init__(module)

        # Set the parameters
        self.state = self.get_param("state")
        self.force = self.get_param("force")
        self.configure_all_services = self.get_param("configure_all_services")
        self.connection_ssh_port = self.get_param("connection_ssh_port")
        self.connection_user_name = self.get_param("connection_user_name")
        self.connection_password = self.get_param("connection_password")
        self.connection_private_key = self.get_param("connection_private_key")
        self.connection_passphrase = self.get_param("connection_passphrase")
        self.custom_ca = self.get_param("custom_ca")
        self.location = self.get_param("location")
        self.interpret_as_filenames = self.get_param("interpret_as_filenames")
        self.cm_host_cert = self.get_param("cm_host_cert")
        self.cm_host_key = self.get_param("cm_host_key")
        self.ca_cert = self.get_param("ca_cert")
        self.keystore_passwd = self.get_param("keystore_passwd")
        self.truststore_passwd = self.get_param("truststore_passwd")
        self.trusted_ca_certs = self.get_param("trusted_ca_certs")
        self.host_certs = self.get_param("host_certs")

        # # Initialize the return values
        self.cm_config = []
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

        # create an instance of the API class
        cm_api_instance = ClouderaManagerResourceApi(self.api_client)

        # Retrieve the cm configuration
        existing = [r.to_dict() for r in self.get_cm_config()]
        self.cm_config = existing  # initialize return value

        # We'll use the AUTO_TLS_TYPE config to determine if AutoTLS is already enabled
        auto_tls_setting = next(
            (item["value"] for item in existing if item["name"] == "AUTO_TLS_TYPE"),
            None,
        )

        if self.state == "present":

            # Enable AutoTLS if not already enabled
            if auto_tls_setting in [None, "NONE"] or self.force:
                if not self.module.check_mode:
                    cmca_result = cm_api_instance.generate_cmca(
                        body=ApiGenerateCmcaArguments(
                            ssh_port=self.connection_ssh_port,
                            user_name=self.connection_user_name,
                            password=self.connection_password,
                            private_key=self.connection_private_key,
                            passphrase=self.connection_passphrase,
                            location=self.location,
                            custom_ca=self.custom_ca,
                            interpret_as_filenames=self.interpret_as_filenames,
                            cm_host_cert=self.cm_host_cert,
                            cm_host_key=self.cm_host_key,
                            ca_cert=self.ca_cert,
                            keystore_passwd=self.keystore_passwd,
                            truststore_passwd=self.truststore_passwd,
                            trusted_ca_certs=self.trusted_ca_certs,
                            host_certs=self.host_certs,
                            configure_all_services=self.configure_all_services,
                        )
                    )

                    if cmca_result.success is False:
                        self.module.fail_json(
                            msg=f"Unable to enable AutoTLS: {cmca_result.result_message}"
                        )

                    # Retrieve cm_config again after enabling TLS
                    self.cm_config = [r.to_dict() for r in self.get_cm_config()]

                    self.changed = True

                if self.module._diff:
                    self.before.update(cm_config=existing)
                    self.after.update(cm_config=self.cm_config)

        elif self.state == "absent":
            # Below CM configuration parameters need to be reset
            reset_params = dict(
                auto_tls_type="NONE",
                agent_tls=False,
                auto_tls_keystore_password="",
                auto_tls_truststore_password="",
                host_cert_generator="",
                keystore_password="",
                keystore_path=None,
                need_agent_validation=False,
                truststore_password="",
                truststore_path=None,
                web_tls=False,
            )

            if auto_tls_setting not in [None, "NONE"]:
                if not self.module.check_mode:
                    body = ApiConfigList(
                        items=[
                            ApiConfig(name=k, value=v) for k, v in reset_params.items()
                        ]
                    )

                    cm_api_instance.update_config(body=body)

                    # Retrieve cm_config again after disabling TLS
                    self.cm_config = [r.to_dict() for r in self.get_cm_config()]
                    self.changed = True

                    if self.module._diff:
                        self.before.update(cm_config=existing)
                        self.after.update(cm_config=self.cm_config)


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            connection_ssh_port=dict(required=False, type="int"),
            connection_user_name=dict(required=False, type="str"),
            connection_password=dict(required=False, type="str", no_log=True),
            connection_private_key=dict(required=False, type="str", no_log=True),
            connection_passphrase=dict(required=False, type="str", no_log=True),
            configure_all_services=dict(required=False, type="bool", default=True),
            custom_ca=dict(required=False, type="bool"),
            force=dict(required=False, type="bool", default=False),
            location=dict(required=False, type="str"),
            interpret_as_filenames=dict(required=False, type="bool", default=True),
            cm_host_cert=dict(required=False, type="str"),
            cm_host_key=dict(required=False, type="str", no_log=True),
            ca_cert=dict(required=False, type="str"),
            keystore_passwd=dict(required=False, type="str", no_log=True),
            truststore_passwd=dict(required=False, type="str", no_log=True),
            trusted_ca_certs=dict(required=False, type="str"),
            host_certs=dict(
                type="list",
                elements="dict",
                options=dict(
                    hostname=dict(),
                    certificate=dict(),
                    key=dict(no_log=True),
                ),
            ),
            state=dict(
                type="str",
                default="present",
                choices=["present", "absent"],
            ),
        ),
        supports_check_mode=True,
        required_if=[
            (
                "custom_ca",
                True,
                (
                    "cm_host_cert",
                    "cm_host_key",
                    "ca_cert",
                    "keystore_passwd",
                    "truststore_passwd",
                ),
                False,
            ),
        ],
    )

    result = ClouderaManagerAutoTLS(module)

    output = dict(
        changed=result.changed,
        cm_config=result.cm_config,
    )
    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
