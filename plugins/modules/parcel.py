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
module: parcel
short_description: Manage the state of parcels on a cluster
description:
  - Facilitates the management of parcels of a CDP cluster according to the specified state.
  - States lie on a continuum from I(absent), i.e. C(available remotely), I(downloaded), I(distributed), and I(activated)/I(present).
  - The module manages the transitions between these states, e.g. if a parcel is I(distributed) and I(state=downloaded), the module will deactivate the parcel from the cluster hosts.
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
      - The name of the product, e.g. CDH, Impala
    type: str
    required: yes
    aliases:
      - parcel
      - product
  parcel_version:
    description:
      - The semantic version of the product, e.g. 1.1.0, 2.3.0.
    type: str
    required: yes
  state:
    description:
      - State of the parcel.
      - I(present) is mapped to I(activated).
    type: str
    default: 'present'
    choices:
      - 'downloaded'
      - 'distributed'
      - 'activated'
      - 'present'
      - 'absent'
    required: False
  timeout:
    description:
      - Timeout, in seconds, before failing when changing state, e.g. V(DISTRIBUTED).
    type: int
    default: 1200
    aliases:
      - polling_timeout
  delay:
    description:
      - Delay (interval), in seconds, between each attempt.
    type: int
    default: 15
    aliases:
      - polling_interval
extends_documentation_fragment:
  - ansible.builtin.action_common_attributes
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  platform:
    platforms: all
"""

EXAMPLES = r"""
- name: Download, distribute and activate a parcel on a cluster
  cloudera.cluster.parcel:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster_name: "Example_Cluster"
    product: "ECS"
    parcel_version: "1.5.1-b626-ecs-1.5.1-b626.p0.42068229"
    state: "activated"

- name: Downloand and distribute a parcel on a cluster
  cloudera.cluster.parcel:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster_name: "Example_Cluster"
    product: "ECS"
    parcel_version: "1.5.1-b626-ecs-1.5.1-b626.p0.42068229"
    state: "distributed"

- name: Remove the parcel on a specified cluster
  cloudera.cluster.parcel:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster_name: "Example_Cluster"
    product: "ECS"
    parcel_version: "1.5.1-b626-ecs-1.5.1-b626.p0.42068229"
    state: "absent"

- name: Undistribute the parcel on a specified cluster (if "distributed" or "activated")
  cloudera.cluster.parcel:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster_name: "Example_Cluster"
    product: "ECS"
    parcel_version: "1.5.1-b626-ecs-1.5.1-b626.p0.42068229"
    state: "downloaded"  # Assuming the current state is "distributed" or "activated"
"""

RETURN = r"""
parcel:
    description: Details about the parcel
    type: dict
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
    Parcel,
    parse_parcel_result,
)

from cm_client import ClustersResourceApi, ParcelResourceApi
from cm_client.rest import ApiException


class ClouderaParcel(ClouderaManagerModule):

    FUNCTION_MAP = {
        "ACTIVATED": "activate",
        "AVAILABLE_REMOTELY": "remove",
        "DISTRIBUTED": "distribute",
        "DOWNLOADED": "download",
    }

    def __init__(self, module):
        super(ClouderaParcel, self).__init__(module)

        # Set parameters
        self.cluster = self.get_param("cluster")
        self.parcel_name = self.get_param("name")
        self.parcel_version = self.get_param("parcel_version")
        self.state = self.get_param("state")
        self.delay = self.get_param("delay")
        self.timeout = self.get_param("timeout")

        # Set outputs
        self.changed = False
        self.diff = {}
        self.output = {}

        # Execute
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        parcel_api = ParcelResourceApi(self.api_client)
        cluster_api = ClustersResourceApi(self.api_client)

        try:
            cluster_api.read_cluster(cluster_name=self.cluster).to_dict()
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(msg=f" Cluster '{self.cluster}' not found")

        try:
            parcel = Parcel(
                parcel_api=parcel_api,
                product=self.parcel_name,
                version=self.parcel_version,
                cluster=self.cluster,
                log=self.module.log,
                delay=self.delay,
                timeout=self.timeout,
            )
        except ApiException as ex:
            if ex.status == 404:
                self.module.fail_json(
                    msg=f"Parcel {self.parcel_name} (version: {self.parcel_version}) not found on cluster '{self.cluster}'"
                )

        # Normalize self.state
        if self.state == "present":
            self.state = "ACTIVATED"
        elif self.state == "absent":
            self.state = "AVAILABLE_REMOTELY"
        else:
            self.state = str(self.state).upper()

        if self.state != parcel.stage:
            self.changed = True

            if self.module._diff:
                self.diff = dict(before=parcel.stage, after=self.state)

            if not self.module.check_mode:
                cmd = getattr(parcel, self.FUNCTION_MAP[self.state])
                cmd()

        self.output = parse_parcel_result(
            parcel_api.read_parcel(
                cluster_name=self.cluster,
                product=self.parcel_name,
                version=self.parcel_version,
            )
        )


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            name=dict(required=True, aliases=["parcel", "product"]),
            parcel_version=dict(required=True),
            delay=dict(
                required=False, type="int", default=15, aliases=["polling_interval"]
            ),
            timeout=dict(
                required=False, type="int", default=1200, aliases=["polling_timeout"]
            ),
            state=dict(
                default="present",
                choices=[
                    "downloaded",
                    "distributed",
                    "activated",
                    "present",
                    "absent",
                ],
            ),
        ),
        supports_check_mode=True,
    )

    result = ClouderaParcel(module)

    changed = result.changed

    output = dict(
        changed=changed,
        parcel=result.output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
