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
module: cm_service_role_info
short_description: Retrieve information about Cloudera Management service roles.
description:
  - Gather information about one or all Cloudera Manager service roles.
author:
  - Webster Mudge (@wmudge)
options:
  type:
    description:
      - The role type of the role.
    type: str
    aliases:
      - role_type
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
attributes:
  check_mode:
    support: full
requirements:
  - cm-client
seealso:
  - module: cloudera.cluster.cm_service_role
"""

EXAMPLES = r"""
- name: Gather details of an individual Cloudera Manager service role.
  cloudera.cluster.cm_service_role_info:
    host: "example.cloudera.host"
    username: "john_doe"
    password: "S&peR4Ec*re"
    type: HOSTMONITOR
  register: cm_output

- name: Gather details of all Cloudera Manager service roles.
  cloudera.cluster.cm_service_role_info:
    host: "example.cloudera.host"
    username: "john_doe"
    password: "S&peR4Ec*re"
  register: cm_output
"""

RETURN = r"""
roles:
  description: List of Cloudera Manager service roles.
  type: list
  elements: dict
  returned: always
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
"""

from cm_client import (
    MgmtServiceResourceApi,
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    parse_role_result,
    read_cm_role,
    read_cm_roles,
)


class ClouderaServiceRoleInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaServiceRoleInfo, self).__init__(module)

        # Set the parameters
        self.type = self.get_param("type")

        # Initialize the return values
        self.output = list()

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        # Confirm that CMS is present
        try:
            MgmtServiceResourceApi(self.api_client).read_service()
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg="Cloudera Management service does not exist")
            else:
                raise ex

        # Retrieve the specified role by type
        if self.type:
            result = None

            try:
                result = read_cm_role(api_client=self.api_client, role_type=self.type)
            except ApiException as ex:
                if ex.status != 404:
                    raise ex

            if result is not None:
                self.output.append(parse_role_result(result))
        else:
            self.output = [
                parse_role_result(r)
                for r in read_cm_roles(api_client=self.api_client).items
            ]


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            type=dict(aliases=["role_type"]),
        ),
        supports_check_mode=False,
    )

    result = ClouderaServiceRoleInfo(module)

    output = dict(
        changed=False,
        roles=result.output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
