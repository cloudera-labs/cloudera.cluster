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
    ClouderaManagerModule,
)

from cm_client import ClustersResourceApi, ParcelResourceApi, ParcelsResourceApi
from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: parcel_info
short_description: Gather details about the parcels on the cluster
description:
  - Gathers details about a single parcel or about all parcels on the cluster
author:
  - "Ronald Suplina (@rsuplina)"
requirements:
  - cm_client
options:
  cluster_name:
    description:
      - The name of the cluster
    type: str
    required: yes
  product:
    description:
      - The name of the product, e.g. CDH, Impala
    type: str
    required: no
  parcel_version:
    description:
      - The version of the product, e.g. 1.1.0, 2.3.0.
    type: str
    required: no
"""

EXAMPLES = r"""
---
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
---
cloudera_manager:
    description: Returns details about specific parcel or all parcels on the cluster
    type: list
    elements: dict
    contains:
        product:
            product: The name of the product.
            type: str
            returned: always
        version:
            description: The version of the product
            type: str
            returned: always
        stage:
            description: Current stage of the parcel.
            type: str
            returned: always
        state:
            description: The state of the parcel. This shows the progress of state transitions and if there were any errors.
            type: dict
            returned: always
        clusterRef:
            description:  A reference to the enclosing cluster.
            type: dict
            returned: always
        displayName:
            description: Display name of the parcel.
            type: str
            returned: always
        description:
            description: Description of the parcel.
            type: str
            returned: always
"""


class ClouderaParcelInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaParcelInfo, self).__init__(module)
        self.cluster_name = self.get_param("cluster_name")
        self.product = self.get_param("product")
        self.parcel_version = self.get_param("parcel_version")
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        parcel_api_instance = ParcelResourceApi(self.api_client)
        parcels_api_instance = ParcelsResourceApi(self.api_client)
        cluster_api_instance = ClustersResourceApi(self.api_client)

        self.parcel_output = {}
        self.changed = False

        try:
            cluster_api_instance.read_cluster(cluster_name=self.cluster_name).to_dict()
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg=f" Cluster {self.cluster_name} {ex.reason}")

        if self.product and self.parcel_version:
            self.parcel_info = parcel_api_instance.read_parcel(
                cluster_name=self.cluster_name,
                product=self.product,
                version=self.parcel_version,
            ).to_dict()
            self.parcel_output = {"items": [self.parcel_info]}
        else:
            self.parcel_output = parcels_api_instance.read_parcels(
                cluster_name=self.cluster_name
            ).to_dict()


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            cluster_name=dict(required=True, type="str"),
            product=dict(required=False, type="str"),
            parcel_version=dict(required=False, type="str"),
        ),
        supports_check_mode=True,
        required_together=[
            ("product", "parcel_version"),
        ],
    )

    result = ClouderaParcelInfo(module)

    changed = result.changed

    output = dict(
        changed=changed,
        cloudera_manager=result.parcel_output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
