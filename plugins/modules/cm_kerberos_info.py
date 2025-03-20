#!/usr/bin/python
# -*- coding: utf-8 -*-
#
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

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from cm_client.rest import ApiException

DOCUMENTATION = r"""
module: cm_kerberos_info
short_description: Retrieve Cloudera Manager configurations for Kerberos
description:
  - Retrieve Cloudera Manager configurations for Kerberos
author:
  - "Jim Enright (@jimright)"
requirements:
  - cm_client
extends_documentation_fragment:
  - ansible.builtin.action_common_attributes
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
attributes:
  check_mode:
    support: full
notes:
  - This is a convenience module to retrieve Kerberos settings from the Cloudera Manager configuration.
  - Using the C(cm_config_info) module will return similar settings.
  - Requires C(cm_client).
seealso:
  - module: cloudera.cluster.cm_config_info
"""

EXAMPLES = r"""
---
- name: Retrieve CM Kerberos settings
  cloudera.cluster.cm_kerberos_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
  register: __kerberos_settings
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


class ClouderaManagerKerberosInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaManagerKerberosInfo, self).__init__(module)

        # Initialize the return values
        self.config = []

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):

        kerberos_cm_settings = [
            "krb_enc_types", "security_realm", "kdc_type",
            "kdc_admin_host", "kdc_host", "krb_auth_enable",
            "ad_account_prefix", "ad_kdc_domain", "ad_delete_on_regenerate",
            "ad_set_encryption_types", "kdc_account_creation_host_override",
            "gen_keytab_script"
        ]

        # Retrieve the cm configuration
        cm_config = [r.to_dict() for r in self.get_cm_config(scope="full")]
        self.config = [r for r in cm_config if r["name"].lower() in kerberos_cm_settings]


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(),
        supports_check_mode=True,
    )

    result = ClouderaManagerKerberosInfo(module)

    output = dict(
        changed=result.changed,
        cm_config=result.config,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
