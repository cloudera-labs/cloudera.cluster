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
module: host_config_info
short_description: Retrieves the configuration details of a specific host.
description:
  - Gather configuration information about a specific host.
author:
  - "Ronald Suplina (@rsuplina)"
version_added: "4.4.0"
deprecated:
  removed_in: "6.0.0"
  alternative: Use M(cloudera.cluster.host_info)
  why: Consolidation of configuration management.
requirements:
  - cm_client
options:
  view:
    description:
      - The view to materialize.
    type: str
    default: full
    choices:
        - full
        - summary
  name:
    description:
      - The ID or name of the host.
    type: str
    required: yes
    aliases:
      - host_id
      - host_name
"""

EXAMPLES = r"""
- name: Gather the configuration details for a host
  cloudera.cluster.host_config_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: example.cloudera.com
    view: summary

- name: Gather the configuration details in 'full' for a host
  cloudera.cluster.host_config_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: example.cloudera.com
    view: full
"""

RETURN = r"""
config:
  description: Configuration details about a specific host.
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
        - Requires I(full) view.
      type: bool
      returned: when supported
    default:
      description:
        - The default value.
        - Requires I(full) view.
      type: str
      returned: when supported
    display_name:
      description:
        - A user-friendly name of the parameters, as would have been shown in the web UI.
        - Requires I(full) view.
      type: str
      returned: when supported
    description:
      description:
        - A textual description of the parameter.
        - Requires I(full) view.
      type: str
      returned: when supported
    related_name:
      description:
        - If applicable, contains the related configuration variable used by the source project.
        - Requires I(full) view.
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
        - Requires I(full) view.
      type: str
      returned: when supported
    validation_message:
      description:
        - A message explaining the parameter's validation state.
        - Requires I(full) view.
      type: str
      returned: when supported
    validation_warnings_suppressed:
      description:
        - Whether validation warnings associated with this parameter are suppressed.
        - In general, suppressed validation warnings are hidden in the Cloudera Manager UI.
        - Configurations that do not produce warnings will not contain this field.
        - Requires I(full) view.
      type: bool
      returned: when supported
"""

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from cm_client import HostsResourceApi
from cm_client.rest import ApiException


class ClouderaHostConfigInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaHostConfigInfo, self).__init__(module)

        # Set the parameters
        self.hostname = self.get_param("name")
        self.view = self.get_param("view")

        # Initialize the return value
        self.host_config_info = []

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):

        try:
            HostsResourceApi(self.api_client).read_host(self.hostname)
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg="Host does not exist: " + self.hostname)
            else:
                raise ex

        host_api_instance = HostsResourceApi(self.api_client)
        host_configs = host_api_instance.read_host_config(
            host_id=self.hostname,
            view=self.view,
        )

        self.host_config_info = [s.to_dict() for s in host_configs.items]


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            name=dict(required=False, type="str", aliases=["host_id", "host_name"]),
            view=dict(default="full", choices=["summary", "full"]),
        ),
        supports_check_mode=True,
    )

    result = ClouderaHostConfigInfo(module)

    output = dict(
        changed=False,
        host_config_info=result.host_config_info,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
