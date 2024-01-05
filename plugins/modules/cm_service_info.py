# Copyright 2023 Cloudera, Inc. All Rights Reserved.
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

from cm_client import MgmtServiceResourceApi

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: cm_service_info
short_description: Retrieve information about the Cloudera Management Services
description:
  - Gather information about the Cloudera Manager service.
author:
  - "Ronald Suplina (@rsuplina)"
requirements:
  - cm_client
"""

EXAMPLES = r"""
---
- name: Gather details using an host
  cloudera.cluster.cm_version:
    host: "example.cloudera.host"
    username: "will_jordan"
    password: "S&peR4Ec*re"
  register: cm_output
"""

RETURN = r"""
---
cloudera_manager:
    description: Details about Cloudera Manager Service
    type: dict
    contains:
        name:
            description: The Cloudera Manager service name.
            type: str
            returned: optional
        type:
            description: The Cloudera Manager service type.
            type: str
            returned: optional
        cluster_ref:
            description: Reference to a cluster.
            type: str
            returned: optional
        service_state:
            description: State of the Cloudera Manager Service.
            type: str
            returned: optional
        health_summary:
            description: Health of the Cloudera Manager Service.
            type: str
            returned: optional
        config_stale:
            description: Configuration state of Cloudera Manager Service.
            type: str
            returned: optional
        config_staleness_status:
            description: Status of configuration staleness for Cloudera Manager Service.
            type: str
            returned: optional
        client_config_staleness_status:
            description: Status of Client configuration for Cloudera Manager Service.
            type: str
            returned: optional
        health_checks:
            description: Lists all available health checks for Cloudera Manager Service.
            type: dict
            returned: optional
        service_url:
            description: Service url for Cloudera Manager Service.
            type: str
            returned: optional
        role_instances_url:
            description: Role instance url for Cloudera Manager Service.
            type: str
            returned: optional
        maintenance_mode:
            description: Maintance mode of Cloudera Manager Service.
            type: bool
            returned: optional
        maintenance_owners:
            description: List of Maintance owners for Cloudera Manager Service.
            type: list
            returned: optional
        config:
            description: Configuration details for Cloudera Manager Service.
            type: dict
            returned: optional
        roles:
            description: Role list of Cloudera Manager Service.
            type: dict
            returned: optional
        display_name:
            description: Display name of Cloudera Manager Service.
            type: dict
            returned: optional
        role_config_groups:
            description: List of role configuration groups for Cloudera Manager Service.
            type: list
            returned: optional
        replication_schedules:
            description: List of replication schedules for Cloudera Manager Service.
            type: list
            returned: optional
        snapshot_policies:
            description: Snapshot policy for Cloudera Manager Service.
            type: str
            returned: optional
        entity_status:
            description: Health status of entities for Cloudera Manager Service.
            type: str
            returned: optional
        tags:
            description: List of tags for Cloudera Manager Service.
            type: list
            returned: optional
        service_version:
            description: Version of Cloudera Manager Service.
            type: str
            returned: optional
"""


class ClouderaServiceInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaServiceInfo, self).__init__(module)

        # Initialize the return values
        self.cm_service_info = dict()

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        api_instance = MgmtServiceResourceApi(self.api_client)
        self.cm_service_info = api_instance.read_service().to_dict()


def main():
    module = ClouderaManagerModule.ansible_module(supports_check_mode=True)

    result = ClouderaServiceInfo(module)

    output = dict(
        changed=False,
        cloudera_manager=result.cm_service_info,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
