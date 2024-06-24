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


from cm_client import (
    HostsResourceApi,
    ApiConfigList,
    ApiConfig,
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerMutableModule,
    resolve_parameter_updates,
)

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: host_config
short_description: Manage a host configuration in Cloudera Manager
description:
  - Manage a host configuration in Cloudera Manager
  - The module supports C(check_mode).
author:
  - "Ronald Suplina (@rsuplina)"
requirements:
  - cm_client
options:
  name:
    description:
      - The ID of the host.
    type: str
    required: yes
    aliases:
      - host_id
      - host_name
  parameters:
    description:
      - The service-wide configuration to set.
      - To unset a parameter, use C(None) as the value.
    type: dict
    required: yes
    aliases:
      - params
  view:
    description:
      - The view to materialize.
    type: str
    default: summary
    choices:
        - summary
        - full
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
"""

EXAMPLES = r"""
---
- name: Update host configuration parameters
  cloudera.cluster.host_config
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: example.cloudera.com
    parameters:
      some_configuration_path: "/usr/bin/java"
      port_configuration: 8777

- name: Reset all host configurations and update specified parameters
  cloudera.cluster.host_config
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: example.cloudera.com
    purge: yes
    parameters:
      some_configuration_path: "/usr/bin/java"
      port_configuration: 8777

"""

RETURN = r"""
---
config:
  description:
    - Configuration details about a specific host.
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


class ClouderaHostConfigInfo(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClouderaHostConfigInfo, self).__init__(module)

        # Set the parameters
        self.hostname = self.get_param("name")
        self.params = self.get_param("parameters")
        self.purge = self.get_param("purge")
        self.view = self.get_param("view")

        # Initialize the return value
        self.changed = False
        self.diff = {}

        self.host_config = []
        # Execute the logic
        self.process()

    @ClouderaManagerMutableModule.handle_process
    def process(self):
        try:
            HostsResourceApi(self.api_client).read_host(self.hostname)
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg="Host does not exist: " + self.hostname)
            else:
                raise ex

        api_instance = HostsResourceApi(self.api_client)
        existing = api_instance.read_host_config(host_id=self.hostname, view=self.view)

        current = {r.name: r.value for r in existing.items}
        incoming = {k: str(v) if v is not None else v for k, v in self.params.items()}

        change_set = resolve_parameter_updates(current, incoming, self.purge)
        if change_set:
            self.changed = True

            if self.module._diff:
                self.diff = dict(
                    before={
                        k: current[k] if k in current else None
                        for k in change_set.keys()
                    },
                    after=change_set,
                )

            if not self.module.check_mode:
                body = ApiConfigList(
                    items=[
                        ApiConfig(name=k, value=f"{v}") for k, v in change_set.items()
                    ]
                )

                self.host_config = [
                    p.to_dict()
                    for p in api_instance.update_host_config(
                        host_id=self.hostname, body=body
                    ).items
                ]
        else:
            self.host_config = [p.to_dict() for p in existing.items]


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            name=dict(required=False, type="str"),
            parameters=dict(type="dict", required=True, aliases=["params"]),
            view=dict(required=False, default="full", choices=["summary", "full"]),
            purge=dict(type="bool", default=False),
        ),
        supports_check_mode=True,
    )

    result = ClouderaHostConfigInfo(module)

    output = dict(
        changed=result.changed,
        host_config=result.host_config,
    )
    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
