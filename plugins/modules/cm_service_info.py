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
module: cm_service_info
short_description: Retrieve information about the Cloudera Management service
description:
  - Gather information about the Cloudera Manager service.
author:
  - Ronald Suplina (@rsuplina)
  - Webster Mudge (@wmudge)
version_added: "4.4.0"
options:
  view:
    description:
      - View type of the returned service details.
    type: str
    required: false
    choices:
      - summary
      - full
      - export
    default: summary
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - ansible.builtin.action_common_attributes
requirements:
  - cm-client
seealso:
  - module: cloudera.cluster.cm_service
  - module: cloudera.cluster.cm_service_role
  - module: cloudera.cluster.cm_service_role_config_group
"""

EXAMPLES = r"""
- name: Gather details of the Cloudera Manager service
  cloudera.cluster.cm_service_info:
    host: "example.cloudera.host"
    username: "will_jordan"
    password: "S&peR4Ec*re"
  register: cm_output
"""

RETURN = r"""
service:
  description: The Cloudera Manager service.
  type: dict
  contains:
    client_config_staleness_status:
      description: Status of client configuration for the Cloudera Manager service.
      type: str
      returned: optional
    cluster_name:
      description: The associated cluster name.
      type: str
      returned: optional
    config:
      description: Service-wide configuration for the Cloudera Manager service.
      type: dict
      returned: optional
    config_staleness_status:
      description: Status of configuration staleness for the Cloudera Manager service.
      type: str
      returned: optional
      sample:
        - FRESH
        - STALE_REFRESHABLE
        - STALE
    display_name:
      description: Display name of the Cloudera Manager service.
      type: str
      returned: always
    health_checks:
      description: Lists all available health checks for the Cloudera Manager service.
      type: list
      elements: dict
      returned: optional
      contains:
        explanation:
          description: A descriptor for the health check.
          type: str
          returned: optional
        name:
          description: Unique name fore the health check.
          type: str
          returned: always
        summary:
          description: The summary status of the health check.
          type: str
          returned: always
          sample:
            - DISABLED
            - HISTORY_NOT_AVAILABLE
            - NOT_AVAILABLE
            - GOOD
            - CONCERNING
            - BAD
        suppressed:
          description:
            - Whether the health check is suppressed.
            - A suppressed health check is not considered when computing the overall health.
          type: bool
          returned: always
    health_summary:
      description: Health of the Cloudera Manager service.
      type: str
      returned: always
      sample:
        - DISABLED
        - HISTORY_NOT_AVAILABLE
        - NOT_AVAILABLE
        - GOOD
        - CONCERNING
        - BAD
    maintenance_mode:
      description: Whether maintance mode is enabled for the Cloudera Manager service.
      type: bool
      returned: always
    maintenance_owners:
      description: List of objects that trigger the Cloudera Manager service to be in maintenance mode.
      type: list
      elements: str
      returned: optional
      sample:
        - CLUSTER
        - SERVICE
        - ROLE
        - HOST
        - CONTROL_PLANE
    name:
      description: Name (identifier) of the Cloudera Manager service.
      type: str
      returned: always
    role_config_groups:
      description: List of role configuration groups for Cloudera Manager service.
      type: list
      elements: dict
      returned: optional
      contains:
        base:
          description: Whether the role config group is a base (default) group.
          type: bool
          returned: always
        config:
          description: Configuration for the role config group.
          type: dict
          returned: optional
        display_name:
          description: Display name for the role config group.
          type: str
          returned: always
        name:
          description: Name (identifier) of the role config group.
          type: str
          returned: always
        role_type:
          description: The type of roles in this group.
          type: str
          returned: always
        service_name:
          description: Name (identifier) of the associated service of the role config group.
          type: str
          returned: always
    roles:
      description: List of role instances for Cloudera Manager service.
      type: list
      elements: dict
      returned: optional
      contains:
        commission_state:
          description: Commission state of the Cloudera Manager service role.
          type: str
          returned: always
          sample:
            - COMMISSIONED
            - DECOMMISSIONING
            - DECOMMISSIONED
            - UNKNOWN
            - OFFLINING
            - OFFLINED
        config:
          description: Role override configuration for the Cloudera Manager service.
          type: dict
          returned: optional
        config_staleness_status:
          description: Status of configuration staleness for the Cloudera Manager service role.
          type: str
          returned: always
          sample:
            - FRESH
            - STALE_REFRESHABLE
            - STALE
        ha_status:
          description: High-availability status for the Cloudera Manager service.
          type: str
          returned: optional
          sample:
            - ACTIVE
            - STANDBY
            - UNKNOWN
        health_checks:
          description: List of all available health checks for Cloudera Manager service role.
          type: list
          elements: dict
          returned: optional
          contains:
            explanation:
              description: The explanation of this health check.
              type: str
              returned: optional
            name:
              description: Unique name of this health check.
              type: str
              returned: always
            summary:
              description: The high-level health status of the health check.
              type: str
              returned: always
              sample:
                - DISABLED
                - HISTORY_NOT_AVAILABLE
                - NOT_AVAILABLE
                - GOOD
                - CONCERNING
                - BAD
            suppressed:
              description:
                - Whether this health check is suppressed.
                - A suppressed health check is not considered when computing the role's overall health.
              type: bool
              returned: optional
        health_summary:
          description: The high-level health status of the Cloudera Manager service role.
          type: str
          returned: always
          sample:
            - DISABLED
            - HISTORY_NOT_AVAILABLE
            - NOT_AVAILABLE
            - GOOD
            - CONCERNING
            - BAD
        host_id:
          description: The unique ID of the cluster host.
          type: str
          returned: always
        maintenance_mode:
          description: Whether the Cloudera Manager service role is in maintenance mode.
          type: bool
          returned: always
        maintenance_owners:
          description: List of objects that trigger the Cloudera Manager service role to be in maintenance mode.
          type: list
          elements: str
          returned: optional
          sample:
            - CLUSTER
            - SERVICE
            - ROLE
            - HOST
            - CONTROL_PLANE
        name:
          description:
            - The Cloudera Manager service role name.
            - Note, this is an auto-generated name and cannot be changed.
          type: str
          returned: always
        role_config_group_name:
          description: The name of the Cloudera Manager Service role config group, which uniquely identifies it in a Cloudera Manager installation.
          type: str
          returned: always
        role_state:
          description: State of the Cloudera Manager service role.
          type: str
          returned: always
          sample:
            - HISTORY_NOT_AVAILABLE
            - UNKNOWN
            - STARTING
            - STARTED
            - STOPPING
            - STOPPED
            - NA
        service_name:
          description: The name of the Cloudera Manager service, which uniquely identifies it in a deployment.
          type: str
          returned: always
        tags:
          description: Set of tags for the Cloudera Manager service role.
          type: dict
          returned: optional
        type:
          description: The Cloudera Manager service role type.
          type: str
          returned: always
          sample:
            - HOSTMONITOR
            - ALERTPUBLISHER
            - SERVICEMONITOR
            - REPORTSMANAGER
            - EVENTSERVER
        zoo_keeper_server_mode:
          description:
            - The Zookeeper server mode for this Cloudera Manager service role.
            - Note that for non-Zookeeper Server roles, this will be V(null).
          type: str
          returned: optional
    service_state:
      description: Run state of the Cloudera Manager service.
      type: str
      returned: always
      sample:
        - HISTORY_NOT_AVAILABLE
        - UNKNOWN
        - STARTING
        - STARTED
        - STOPPING
        - STOPPED
        - NA
    service_version:
      description: Version of Cloudera Manager service.
      type: str
      returned: always
    tags:
      description: List of tags for Cloudera Manager service.
      type: list
      returned: optional
    type:
      description: Type of the Cloudera Manager service, i.e. MGMT.
      type: str
      returned: always
      sample:
        - MGMT
"""

from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.service_utils import (
    parse_service_result,
    read_cm_service,
)


class ClouderaServiceInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaServiceInfo, self).__init__(module)

        # Set the parameters
        self.view = self.get_param("view")

        # Initialize the return values
        self.output = dict()

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        result = None
        try:
            result = read_cm_service(api_client=self.api_client, view=self.view)
        except ApiException as ex:
            if ex.status != 404:
                raise ex

        if result is not None:
            self.output = parse_service_result(result)


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            view=dict(
                default="summary",
                choices=["summary", "full"],
            ),
        ),
        supports_check_mode=True,
    )

    result = ClouderaServiceInfo(module)

    output = dict(
        changed=False,
        service=result.output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
