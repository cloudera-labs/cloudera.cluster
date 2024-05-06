# -*- coding: utf-8 -*-

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
    ClouderaManagerMutableModule,
    parse_service_result,
    resolve_tag_updates,
)

from cm_client import (
    ApiEntityTag,
    ApiService,
    ApiServiceList,
    ClustersResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: service
short_description: Manage a service in cluster 
description:
  - Manage a service in a cluster.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
options:
  cluster:
    description:
      - The associated cluster.
    type: str
    required: yes
    aliases:
      - cluster_name
  service:
    description:
      - The service.
    type: str
    required: yes
    aliases:
      - service_name
      - name
  display_name:
    description:
      - The Cloudera Manager UI display name for the service.
    type: str
  maintenance:
    description:
      - Flag for whether the service should be in maintenance mode.
    type: bool
    aliases:
      - maintenance_mode
  tags:
    description:
      - A set of tags applied to the service.
      - To unset a tag, use C(None) as its value.
    type: dict
  type:
    description:
      - The service type.
      - Required if I(state) creates a new service.
    type: str
    aliases:
      - service_type
  purge:
    description:
      - Flag for whether the declared service tags should append or overwrite any existing tags.
      - To clear all tags, set I(tags={}), i.e. an empty dictionary, and I(purge=True).
    type: bool
    default: False
  state:
    description:
      - The state of the service.
    type: str
    default: present
    choices:
      - present
      - absent
      - restarted
      - started
      - stopped
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
"""

EXAMPLES = r"""
---
- name: Establish a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    type: ECS
    display_name: Example ECS
    

- name: Stop a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    state: stopped
    
- name: Force a restart of a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    state: restarted
    
- name: Set a cluster service into maintenance mode
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    maintenance: yes
    
- name: Update (append) several tags on a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    tags:
      tag_one: valueOne
      tag_two: valueTwo
      
- name: Update (purge) the tags on a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    tags:
      tag_three: value_three
    purge: yes
    
- name: Remove all the tags on a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    tags: {}
    purge: yes    

- name: Remove a cluster service
  cloudera.cluster.service:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example_cluster
    service: example_ecs
    state: absent
"""

RETURN = r"""
---
service:
  description: Details about the service.
  type: dict
  contains:
    name:
      description: The cluster service name.
      type: str
      returned: always
    type:
      description: The cluster service type.
      type: str
      returned: always
      sample:
        - HDFS
        - HBASE
        - ECS
    cluster_ref:
      description: The associated cluster reference.
      type: dict
      returned: always
      contains:
        cluster_name:
          description: The name of the cluster, which uniquely identifies it in a Cloudera Manager installation.
          type: str
          returned: always
        display_name:
          description: The display name of the cluster.
          type: str
          returned: when supported
    service_state:
      description: State of the service.
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
    health_summary:
      description: The high-level health status of the service.
      type: str
      returned: always
      sample:
        - DISABLED
        - HISTORY_NOT_AVAILABLE
        - NOT_AVAILABLE
        - GOOD
        - CONCERNING
        - BAD
    config_staleness_status:
      description: Status of configuration staleness for the service.
      type: str
      returned: always
      sample:
        - FRESH
        - STALE_REFRESHABLE
        - STALE
    client_config_staleness_status:
      description: Status of the client configuration for the service.
      type: str
      returned: always
      sample:
        - FRESH
        - STALE_REFRESHABLE
        - STALE
    health_checks:
      description: Lists all available health checks for Cloudera Manager Service.
      type: list
      elements: dict
      returned: when supported
      contains:
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
        explanation:
          description: The explanation of this health check.
          type: str
          returned: when supported
        suppressed:
          description:
            - Whether this health check is suppressed.
            - A suppressed health check is not considered when computing the service's overall health.
          type: bool
          returned: when supported
    maintenance_mode:
      description: Whether the service is in maintenance mode.
      type: bool
      returned: when supported
    maintenance_owners:
      description: The list of objects that trigger this service to be in maintenance mode.
      type: list
      elements: str
      returned: when supported
      sample:
        - CLUSTER
        - SERVICE
        - ROLE
        - HOST
        - CONTROL_PLANE
    display_name:
      description: The display name for the service that is shown in the Cloudera Manager UI.
      type: str
      returned: when supported
    tags:
      description: The dictionary of tags for the service.
      type: dict
      returned: when supported
    service_version:
      description: Version of the service.
      type: str
      returned: when supported
"""


class ClusterService(ClouderaManagerMutableModule):
    def __init__(self, module):
        super(ClusterService, self).__init__(module)

        # Set the parameters
        self.cluster = self.get_param("cluster")
        self.service = self.get_param("service")
        self.maintenance = self.get_param("maintenance")
        self.display_name = self.get_param("display_name")
        self.tags = self.get_param("tags")
        self.type = self.get_param("type")
        self.state = self.get_param("state")
        self.purge = self.get_param("purge")

        # Initialize the return values
        self.changed = False
        self.diff = dict(before={}, after={})
        self.output = {}

        # Execute the logic
        self.process()

    @ClouderaManagerMutableModule.handle_process
    def process(self):
        try:
            ClustersResourceApi(self.api_client).read_cluster(self.cluster)
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg="Cluster does not exist: " + self.cluster)
            else:
                raise ex

        api_instance = ServicesResourceApi(self.api_client)
        existing = None

        try:
            existing = api_instance.read_service(
                self.cluster, self.service, view="full"
            )
        except ApiException as ex:
            if ex.status != 404:
                raise ex

        if self.state == "absent":
            if existing:
                api_instance.delete_service(self.cluster, self.service)

        elif self.state in ["present", "started", "stopped"]:
            if existing:

                # Handle maintenance mode
                if (
                    self.maintenance is not None
                    and self.maintenance != existing.maintenance_mode
                ):
                    self.changed = True

                    if self.module._diff:
                        self.diff["before"].update(
                            maintenance_mode=existing.maintenance_mode
                        )
                        self.diff["after"].update(maintenance_mode=self.maintenance)

                    if not self.module.check_mode:
                        if self.maintenance:
                            maintenance_cmd = api_instance.enter_maintenance_mode(
                                self.cluster, self.service
                            )
                        else:
                            maintenance_cmd = api_instance.exit_maintenance_mode(
                                self.cluster, self.service
                            )

                        if maintenance_cmd.success is False:
                            self.module.fail_json(
                                msg=f"Unable to set Maintenance mode to '{self.maintenance}': {maintenance_cmd.result_message}"
                            )

                # Tags
                if self.tags:
                    (delta_add, delta_del) = resolve_tag_updates(
                        {t.name: t.value for t in existing.tags}, self.tags, self.purge
                    )

                    if delta_add or delta_del:
                        self.changed = True

                        if self.module._diff:
                            self.diff["before"].update(tags=delta_del)
                            self.diff["after"].update(tags=delta_add)

                        if not self.module.check_mode:
                            if delta_del:
                                api_instance.delete_tags(
                                    self.cluster,
                                    self.service,
                                    body=[
                                        ApiEntityTag(k, v) for k, v in delta_del.items()
                                    ],
                                )
                            if delta_add:
                                api_instance.add_tags(
                                    self.cluster,
                                    self.service,
                                    body=[
                                        ApiEntityTag(k, v) for k, v in delta_add.items()
                                    ],
                                )

                # TODO Config

                # Service details
                # Currently, only display_name
                delta = dict()

                if self.display_name and self.display_name != existing.display_name:
                    delta.update(display_name=self.display_name)

                if delta:
                    self.changed = True

                    if self.module._diff:
                        self.diff["before"].update(display_name=existing.display_name)
                        self.diff["after"].update(display_name=self.display_name)

                    if not self.module.check_mode:
                        api_instance.update_service(
                            self.cluster, self.service, body=ApiService(**delta)
                        )

                if self.state == "started" and existing.service_state != "STARTED":
                    self.changed = True

                    if self.module._diff:
                        self.diff["before"].update(service_state=existing.service_state)
                        self.diff["after"].update(service_state="STARTED")

                    if not self.module.check_mode:
                        if existing.service_state == "NA":
                            self.wait_command(
                                api_instance.first_run(self.cluster, self.service)
                            )
                        else:
                            self.wait_command(
                                api_instance.start_command(self.cluster, self.service)
                            )

                elif self.state == "stopped" and existing.service_state not in [
                    "STOPPED",
                    "NA",
                ]:
                    self.changed = True

                    if self.module._diff:
                        self.diff["before"].update(service_state=existing.service_state)
                        self.diff["after"].update(service_state="STOPPED")

                    if not self.module.check_mode:
                        self.wait_command(
                            api_instance.stop_command(self.cluster, self.service)
                        )

                if self.changed:
                    self.output = parse_service_result(
                        api_instance.read_service(
                            self.cluster, self.service, view="full"
                        )
                    )
                else:
                    self.output = parse_service_result(existing)
            else:

                # Service doesn't exist
                if self.type is None:
                    self.module.fail_json(
                        msg=f"Service does not exist, missing required arguments: type"
                    )

                payload = dict(name=self.service, type=str(self.type).upper())

                if self.display_name:
                    payload.update(display_name=self.display_name)

                service_list = ApiServiceList([ApiService(**payload)])

                self.changed = True

                if self.module._diff:
                    self.diff = dict(
                        before={},
                        after=payload,
                    )

                if not self.module.check_mode:
                    api_instance.create_services(self.cluster, body=service_list)

                    if self.state == "started":
                        self.wait_command(
                            api_instance.first_run(self.cluster, self.service)
                        )

                self.output = parse_service_result(
                    api_instance.read_service(self.cluster, self.service, view="full")
                )
        else:
            self.module.fail_json(msg=f"Invalid state: {self.state}")


def main():
    module = ClouderaManagerMutableModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            service=dict(required=True, aliases=["service_name", "name"]),
            maintenance=dict(type="bool", aliases=["maintenance_mode"]),
            display_name=dict(),
            tags=dict(type=dict),
            purge=dict(type="bool", default=False),
            type=dict(aliases=["service_type"]),
            state=dict(
                default="present", choices=["present", "absent", "started", "stopped"]
            ),
        ),
        supports_check_mode=True,
    )

    result = ClusterService(module)

    output = dict(
        changed=result.changed,
        service=result.output,
    )

    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
