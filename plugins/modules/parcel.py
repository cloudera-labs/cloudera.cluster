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

from cm_client import ClustersResourceApi, ParcelResourceApi
from cm_client.rest import ApiException
import time

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: parcel
short_description: Manage the state of parcels on a Cluster
description:
  - Facilitates the management of parcels on a Cluster by downloading, distributing, and activating them according to the specified state.
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
    required: yes
  version:
    description:
      - The version of the product, e.g. 1.1.0, 2.3.0.
    type: str
    required: yes
  state:
    description:
      - State of the parcel.
    type: str
    default: 'activated'
    choices:
      - 'downloaded'
      - 'distributed'
      - 'activated'
      - 'removed'
      - 'undistributed'
      - 'deactivated'
    required: False
"""

EXAMPLES = r"""
---
- name: Download, distribute and activate a parcel on a cluster 
  cloudera.cluster.parcel:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster_name: "OneNodeECS"
    product: "ECS"
    parcel_version: "1.5.1-b626-ecs-1.5.1-b626.p0.42068229"
    state: "activated"

- name: Downloand and distribute a parcel on a cluster 
  cloudera.cluster.parcel:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster_name: "OneNodeECS"
    product: "ECS"
    parcel_version: "1.5.1-b626-ecs-1.5.1-b626.p0.42068229"
    state: "distributed"

- name: Remove the parcel on a specified cluster 
  cloudera.cluster.parcel:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster_name: "OneNodeECS"
    product: "ECS"
    parcel_version: "1.5.1-b626-ecs-1.5.1-b626.p0.42068229"
    state: "removed"

- name: Undistribute the parcel on a specified cluster 
  cloudera.cluster.parcel:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster_name: "OneNodeECS"
    product: "ECS"
    parcel_version: "1.5.1-b626-ecs-1.5.1-b626.p0.42068229"
    state: "undistributed"

"""

RETURN = r"""
---
cloudera_manager:
    description: Returns details about specific parcel
    type: dict
    contains:
        product:
            product: The name of the product.
            type: str
            returned: optional
        version:
            description: The version of the product
            type: str
            returned: optional
        stage:
            description: Current stage of the parcel.
            type: str
            returned: optional
        state:
            description: The state of the parcel. This shows the progress of state transitions and if there were any errors.
            type: dict
            returned: optional
        clusterRef:
            description:  A reference to the enclosing cluster.
            type: dict
            returned: optional
        displayName:
            description: Display name of the parcel.
            type: str
            returned: optional
        description:
            description: Description of the parcel.
            type: str
            returned: optional
"""


class ClouderaParcel(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaParcel, self).__init__(module)

        self.cluster_name = self.get_param("cluster_name")
        self.product = self.get_param("product")
        self.parcel_version = self.get_param("parcel_version")
        self.state = self.get_param("state")
        self.polling_interval = self.get_param("polling_interval")
        self.process()


    def deactivate_parcel(self, parcel_api_instance, cluster_name, product, parcel_version, polling_interval, timeout=600):
        start_time = time.time()
        parcel_api_instance.deactivate_command(cluster_name=cluster_name, product=product, version=parcel_version)
        while True:
            elapsed_time = time.time() - start_time
            if elapsed_time > timeout:
                self.module.fail_json(msg="Timeout exceeded while waiting for parcel state to complete.")
            parcel_status = parcel_api_instance.read_parcel(cluster_name=cluster_name, product=product, version=parcel_version)
            if parcel_status.stage == 'ACTIVATED':
                time.sleep(polling_interval)
            elif parcel_status.stage == "DISTRIBUTED":
                break

    def undistribute_parcel(self, parcel_api_instance, cluster_name, product, parcel_version, polling_interval, timeout=600):
        start_time = time.time()
        parcel_api_instance.start_removal_of_distribution_command(cluster_name=cluster_name, product=product, version=parcel_version)
        while True:
            elapsed_time = time.time() - start_time
            if elapsed_time > timeout:
                self.module.fail_json(msg="Timeout exceeded while waiting for parcel state to complete.")
            parcel_status = parcel_api_instance.read_parcel(cluster_name=cluster_name, product=product, version=parcel_version)
            if parcel_status.stage == 'UNDISTRIBUTING':
                time.sleep(polling_interval)
            elif parcel_status.stage == "DOWNLOADED":
                break

    def remove_parcel(self, parcel_api_instance, cluster_name, product, parcel_version, polling_interval, timeout=600):
        start_time = time.time()
        parcel_api_instance.remove_download_command(cluster_name=cluster_name, product=product, version=parcel_version)
        while True:
            elapsed_time = time.time() - start_time
            if elapsed_time > timeout:
                self.module.fail_json(msg="Timeout exceeded while waiting for parcel state to complete.")
            parcel_status = parcel_api_instance.read_parcel(cluster_name=cluster_name, product=product, version=parcel_version)
            if parcel_status.stage == 'DOWNLOADED':
                time.sleep(polling_interval)
            elif parcel_status.stage == "AVAILABLE_REMOTELY":
                break

    def download_parcel(self, parcel_api_instance, cluster_name, product, parcel_version, polling_interval, timeout=1200):
        start_time = time.time()
        parcel_api_instance.start_download_command(cluster_name=cluster_name, product=product, version=parcel_version)
        while True:
            elapsed_time = time.time() - start_time
            if elapsed_time > timeout:
                self.module.fail_json(msg="Timeout exceeded while waiting for parcel state to complete.")
            parcel_status = parcel_api_instance.read_parcel(cluster_name=cluster_name, product=product, version=parcel_version)
            if parcel_status.stage == 'DOWNLOADING':
                time.sleep(polling_interval)
            elif parcel_status.stage == "DOWNLOADED":
                break

    def distribute_parcel(self, parcel_api_instance, cluster_name, product, parcel_version, polling_interval, timeout=1200):
        start_time = time.time()
        parcel_api_instance.start_distribution_command(cluster_name=cluster_name, product=product, version=parcel_version)
        while True:
            elapsed_time = time.time() - start_time
            if elapsed_time > timeout:
                self.module.fail_json(msg="Timeout exceeded while waiting for parcel state to complete.")
            parcel_status = parcel_api_instance.read_parcel(cluster_name=cluster_name, product=product, version=parcel_version)
            if parcel_status.stage == 'DISTRIBUTING':
                time.sleep(polling_interval)
            elif parcel_status.stage == "DISTRIBUTED":
                break

    def activate_parcel(self, parcel_api_instance, cluster_name, product, parcel_version, polling_interval):
        parcel_api_instance.activate_command(cluster_name=cluster_name, product=product, version=parcel_version)
        while True:
            parcel_status = parcel_api_instance.read_parcel(cluster_name=cluster_name, product=product, version=parcel_version)
            if parcel_status.stage == 'ACTIVATING':
                time.sleep(polling_interval)
            elif parcel_status.stage == "ACTIVATED":
                break


    @ClouderaManagerModule.handle_process
    def process(self):
        parcel_api_instance = ParcelResourceApi(self.api_client)
        cluster_api_instance = ClustersResourceApi(self.api_client)

        self.parcel_output  = {}
        self.changed = False
        parcel_actions = []

        try:
            cluster_api_instance.read_cluster(cluster_name=self.cluster_name).to_dict()
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg=f" Cluster {self.cluster_name} {ex.reason}")

        try: 
            existing_state = parcel_api_instance.read_parcel(cluster_name=self.cluster_name, product=self.product, version=self.parcel_version).stage
        except ApiException as ex:
                if ex.status == 404:
                    self.module.fail_json(msg=f" Parcel {self.parcel_version} {ex.reason}")


        if self.state == "downloaded":
            if existing_state == 'AVAILABLE_REMOTELY':
                parcel_actions.append(self.download_parcel)

        elif self.state == "distributed":
            if existing_state == 'AVAILABLE_REMOTELY':
                parcel_actions.extend([self.download_parcel, self.distribute_parcel])
            elif existing_state == 'DOWNLOADED':
                parcel_actions.append(self.distribute_parcel)

        elif self.state == "activated":
            if existing_state == 'AVAILABLE_REMOTELY':
                parcel_actions.extend([self.download_parcel, self.distribute_parcel, self.activate_parcel])
            elif existing_state == 'DOWNLOADED':
                parcel_actions.extend([self.distribute_parcel, self.activate_parcel])
            elif existing_state == 'DISTRIBUTED':
                parcel_actions.append(self.activate_parcel)


        if self.state == "removed":
            if existing_state == 'DOWNLOADED':
                parcel_actions.append(self.remove_parcel)
            if existing_state == 'DISTRIBUTED':
                parcel_actions.extend([self.undistribute_parcel, self.remove_parcel])
            if existing_state == 'ACTIVATED':
                parcel_actions.extend([self.deactivate_parcel, self.undistribute_parcel, self.remove_parcel])

        if self.state == "undistributed":
            if existing_state == 'DISTRIBUTED':
                parcel_actions.extend([self.undistribute_parcel])
            if existing_state == 'ACTIVATED':
                parcel_actions.extend([self.deactivate_parcel, self.undistribute_parcel])

        if self.state == "deactivated":
            if existing_state == 'ACTIVATED':
                parcel_actions.append(self.deactivate_parcel)



        if existing_state not in ['AVAILABLE_REMOTELY','DOWNLOADED','DISTRIBUTED','ACTIVATED']:
            error_msg = parcel_api_instance.read_parcel(cluster_name=self.cluster_name, product=self.product, version=self.parcel_version).state.errors[0]
            self.module.fail_json(msg=error_msg)

        if not self.module.check_mode:
            for action in parcel_actions:
                action(parcel_api_instance, self.cluster_name, self.product, self.parcel_version, self.polling_interval)
                self.changed = True

        self.parcel_output = parcel_api_instance.read_parcel(cluster_name=self.cluster_name, product=self.product, version=self.parcel_version).to_dict()


def main():
    module = ClouderaManagerModule.ansible_module(
           argument_spec=dict(
            cluster_name=dict(required=True, type="str"),
            product=dict(required=True, type="str"),
            polling_interval=dict(required=False, type="int",default=10),
            parcel_version=dict(required=True, type="str"),
            state=dict(type='str', default='activated', choices=['downloaded', 'distributed','activated','removed','undistributed','deactivated']),
                          ),

        supports_check_mode=True)

    result = ClouderaParcel(module)

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
