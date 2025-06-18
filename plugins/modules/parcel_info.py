#!/usr/bin/python
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

DOCUMENTATION = r"""
module: parcel_info
short_description: Gather details about the parcels on the cluster
description:
  - Gathers details about a single parcel or about all parcels on the cluster
author:
  - "Ronald Suplina (@rsuplina)"
requirements:
  - cm-client
options:
  cluster:
    description:
      - The name of the cluster
    type: str
    required: yes
    aliases:
      - cluster_name
  name:
    description:
      - The name of the product, e.g. CDH, Impala.
      - Required if I(parcel_version) is declared.
    type: str
    required: no
    aliases:
      - product
      - parcel
  parcel_version:
    description:
      - The version of the product, e.g. 1.1.0, 2.3.0.
      - Required if I(name) is declared.
    type: str
    required: no
"""

EXAMPLES = r"""
- name: Gather details about specific parcel
  cloudera.cluster.parcel_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster_name: "OneNodeECS"
    product: "ECS"
    parcel_version: "1.5.1-b626-ecs-1.5.1-b626.p0.42068229"

- name: Gather details about all parcels on the cluster
  cloudera.cluster.parcel_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster_name: "OneNodeECS"
"""

RETURN = r"""
parcels:
    description: Returns details about a specific parcel or all parcels on the cluster
    type: list
    elements: dict
    contains:
        product:
            description: The name of the product.
            type: str
            returned: always
        version:
            description: The version of the product.
            type: str
            returned: always
        stage:
            description: Current stage of the parcel.
            type: str
            returned: always
        state:
            description:
                - The state of the parcel.
                - This shows the progress of state transitions and if there were any errors.
            type: dict
            returned: when supported
        cluster_name:
            description: The name of the enclosing cluster.
            type: dict
            returned: always
        display_name:
            description: Display name of the parcel.
            type: str
            returned: when supported
        description:
            description: Description of the parcel.
            type: str
            returned: when supported
"""

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.parcel_utils import (
    parse_parcel_result,
)

from cm_client import ClustersResourceApi, ParcelResourceApi, ParcelsResourceApi
from cm_client.rest import ApiException


class ClouderaParcelInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaParcelInfo, self).__init__(module)

        self.cluster = self.get_param("cluster")
        self.parcel = self.get_param("name")
        self.parcel_version = self.get_param("parcel_version")

        self.output = {}
        self.changed = False

        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):

        parcel_api = ParcelResourceApi(self.api_client)
        parcels_api = ParcelsResourceApi(self.api_client)
        cluster_api = ClustersResourceApi(self.api_client)

        try:
            cluster_api.read_cluster(cluster_name=self.cluster)
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg=f"Cluster '{self.cluster}' not found")

        if self.parcel and self.parcel_version:
            try:
                parcel_info = parcel_api.read_parcel(
                    cluster_name=self.cluster,
                    product=self.parcel,
                    version=self.parcel_version,
                )
                self.output = [parse_parcel_result(parcel_info)]
            except ApiException as ex:
                if ex.status == 404:
                    pass
        else:
            self.output = [
                parse_parcel_result(p)
                for p in parcels_api.read_parcels(cluster_name=self.cluster).items
            ]


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            name=dict(aliases=["product", "parcel"]),
            parcel_version=dict(),
        ),
        supports_check_mode=True,
        required_together=[
            ("name", "parcel_version"),
        ],
    )

    result = ClouderaParcelInfo(module)

    output = dict(
        changed=result.changed,
        parcels=result.output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
