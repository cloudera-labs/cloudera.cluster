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
module: cluster_info
short_description: Retrieve details about one or more clusters
description:
  - Retrieves details about one or more clusters managed by Cloudera Manager
author:
  - "Ronald Suplina (@rsuplina)"
version_added: "4.4.0"
options:
  name:
    description:
      - Name of Cloudera Manager cluster.
      - This parameter specifies the name of the cluster from which data will be gathered.
      - Mutually exclusive with O(cluster_type).
    type: str
    required: False
    aliases:
      - cluster_name
      - cluster
  cluster_type:
    description:
      - Filter clusters by type when listing clusters.
      - Valid values are V(any), V(base), V(compute), and V(experience).
      - When omitted or null, the API default is used, which is V(base).
      - Mutually exclusive with O(name), including when explicitly set to null.
    type: str
    aliases:
      - type
requirements:
  - cm_client
"""

EXAMPLES = r"""
- name: Get information about the cluster
  cloudera.cluster.cluster_info:
    host: example.cloudera.com
    username: "jane_smith"
    name: "OneNodeCluster"
    password: "S&peR4Ec*re"
    port: "7180"

- name: Get information about all clusters
  cloudera.cluster.cluster_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: "7180"
    type: any
"""

RETURN = r"""
clusters:
    description: Details about a Cloudera Manager cluster or clusters
    type: list
    elements: dict
    contains:
        name:
            description: The name of the cluster.
            type: str
            returned: always
        display_name:
            description: The name of the cluster displayed in the Cloudera Manager UI.
            type: str
            returned: always
        entity_status:
            description: Health status of the cluster.
            type: str
            returned: always
        version:
            description: Version of the cluster installed.
            type: str
            returned: always
        maintenance_mode:
            description: Maintance mode of cluster.
            type: bool
            returned: always
        maintenance_owners:
            description: List of maintance owners for cluster.
            type: list
            returned: always
        cluster_type:
            description: The type of cluster.
            type: str
            returned: always
        tags:
            description: List of tags for cluster.
            type: list
            returned: always
        uuid:
            description: The unique ID of the cluster.
            type: bool
            returned: always
"""

from ansible.module_utils.basic import to_native

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.cluster_utils import (
    parse_cluster_result,
)

from cm_client.rest import ApiException
from cm_client import ClustersResourceApi


class ClusterInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClusterInfo, self).__init__(module)
        self.name = self.get_param("name")
        self.cluster_type = self.get_param("cluster_type")
        self.output = []
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        try:
            cluster_api_instance = ClustersResourceApi(self.api_client)
            if self.name:
                self.output = [
                    parse_cluster_result(
                        cluster_api_instance.read_cluster(cluster_name=self.name),
                    ),
                ]
            else:
                if self.cluster_type is None:
                    clusters = cluster_api_instance.read_clusters()
                else:
                    clusters = cluster_api_instance.read_clusters(
                        cluster_type=self.cluster_type,
                    )
                self.output = [parse_cluster_result(c) for c in clusters.items]

        except ApiException as e:
            if e.status == 404:
                pass
            else:
                raise e
        # except KeyError as ke:
        #     self.module.fail_json(
        #         msg="Invalid result object from Cloudera Manager API",
        #         error=to_native(ke),
        #     )


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            name=dict(aliases=["cluster_name", "cluster"]),
            cluster_type=dict(
                type="str",
                aliases=["type"],
            ),
        ),
        mutually_exclusive=[["name", "cluster_type"]],
        supports_check_mode=True,
    )

    # Ansible's choices validation rejects explicitly supplied null values.
    cluster_type = module.params["cluster_type"]
    if cluster_type is not None and cluster_type not in (
        "any",
        "base",
        "compute",
        "experience",
    ):
        module.fail_json(
            msg="value of cluster_type must be one of: any, base, compute, experience, got: %s"
            % cluster_type,
        )

    result = ClusterInfo(module)

    output = dict(
        changed=False,
        clusters=result.output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
