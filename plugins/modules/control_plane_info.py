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
module: control_plane_info
short_description: Retrieve information about control planes
description:
  - Gather information about control planes in Cloudera on-premise deployments.
  - Returns details about available control planes including their configuration, versions, and metadata.
author:
  - "Jim Enright (@jimright)"
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
attributes:
  check_mode:
    support: full
requirements:
  - cm-client
seealso:
  - module: cloudera.cluster.cluster
"""

EXAMPLES = r"""
- name: Gather information about all control planes
  cloudera.cluster.control_plane_info:
    host: "example.cloudera.host"
    username: "admin"
    password: "admin_password"
  register: control_planes_output
"""

RETURN = r"""
control_planes:
  description: List of control planes in the Cloudera Manager deployment.
  type: list
  elements: dict
  returned: always
  contains:
    namespace:
      description: The namespace where the control plane is installed.
      type: str
      returned: optional
    dns_suffix:
      description: The domain where the control plane is installed.
      type: str
      returned: optional
    uuid:
      description: The universally unique ID of this control plane in Cloudera Manager.
      type: str
      returned: optional
    remote_repo_url:
      description: The URL of the remote repository where the artifacts used to install the control plane are hosted.
      type: str
      returned: optional
    version:
      description: The CDP version of the control plane.
      type: str
      returned: optional
    manifest:
      description: The content of the manifest JSON of the control plane.
      type: str
      returned: optional
    values_yaml:
      description: The content of the values YAML used to configure the control plane.
      type: str
      returned: optional
    tags:
      description: Tags associated with the control plane.
      type: list
      elements: dict
      returned: optional
      contains:
        name:
          description: The name of the tag.
          type: str
          returned: always
        value:
          description: The value of the tag.
          type: str
          returned: always
    kubernetes_type:
      description: The Kubernetes type on which the control plane is running.
      type: str
      returned: optional
"""

from cm_client.rest import ApiException
from cm_client import ControlPlanesResourceApi

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.cluster_utils import (
    parse_control_plane_result,
)


class ControlPlaneInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ControlPlaneInfo, self).__init__(module)

        # Initialize the return values
        self.output = []

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        """Retrieve control plane information from Cloudera Manager API."""
        try:
            api_instance = ControlPlanesResourceApi(self.api_client)
            control_planes = api_instance.get_control_planes().items

            self.output = [parse_control_plane_result(cp) for cp in control_planes]

        except ApiException as e:
            if e.status == 404:
                # No control planes found, return empty list
                self.output = []

def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(),
        supports_check_mode=True,
    )

    result = ControlPlaneInfo(module)

    output = dict(
        changed=False,
        control_planes=result.output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)

if __name__ == "__main__":
    main()
