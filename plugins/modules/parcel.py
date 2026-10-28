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
module: parcel
short_description: Manage the state of parcels on a cluster
description:
  - Facilitates the management of parcels of a CDP cluster according to the specified state.
  - States lie on a continuum from I(absent), i.e. C(available remotely), I(downloaded), I(distributed), and I(activated)/I(present).
  - The module manages the transitions between these states, e.g. if a parcel is I(distributed) and I(state=downloaded), the module will deactivate the parcel from the cluster hosts.
author:
  - "Ronald Suplina (@rsuplina)"
version_added: "4.4.0"
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
      - Required, together with O(parcel_version), unless O(parcels) is set.
    type: str
    aliases:
      - parcel
      - product
  parcel_version:
    description:
      - The semantic version of the product, e.g. 1.1.0, 2.3.0.
      - Required, together with O(name), unless O(parcels) is set.
    type: str
  parcels:
    description:
      - A list of parcels to move to the same O(state), processed in parallel.
      - Use this instead of looping over the module to download, distribute, and activate several parcels at the same time.
      - Mutually exclusive with O(name) and O(parcel_version).
      - The parcels are returned in RV(parcels), in the order given.
      - If any parcel fails, the module waits for the remaining parcels to finish and then fails, reporting each failure in RV(failures).
    type: list
    elements: dict
    suboptions:
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
  max_workers:
    description:
      - The maximum number of parcels to process at the same time when O(parcels) is set.
      - Parcels beyond this limit wait for a free slot.
      - Must be at least 1.
    type: int
    default: 4
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
      - Applies to each parcel individually. Parcels processed in parallel share network bandwidth, so large parcels may need a higher value.
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

- name: Download, distribute and activate several parcels on a cluster in parallel
  cloudera.cluster.parcel:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster_name: "Example_Cluster"
    parcels:
      - product: "CDH"
        parcel_version: "7.3.2-1.cdh7.3.2.p20000.83281140"
      - product: "FLINK"
        parcel_version: "1.20.5-csa1.18.0.0-82229597"
    max_workers: 4
    state: "activated"

- name: Activate parcels defined as a product-to-version dictionary in parallel
  cloudera.cluster.parcel:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster_name: "Example_Cluster"
    parcels: "{{ cloudera_parcels | dict2items(key_name='name', value_name='parcel_version') }}"
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
parcels:
    description:
        - Details about each parcel, in the order given in O(parcels).
        - Each item has the same fields as RV(parcel).
    type: list
    elements: dict
    returned: when O(parcels) is set
parcel:
    description:
        - Details about the parcel given with O(name) and O(parcel_version).
    type: dict
    returned: when O(parcels) is not set
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
failures:
    description:
        - The parcels that did not reach the requested state, with the reason for each.
        - The module fails when this list is not empty.
    type: list
    elements: dict
    returned: on failure, when O(parcels) is set
    version_added: "5.1.0"
    contains:
        product:
            description: The name of the product.
            type: str
            returned: always
        version:
            description: The version of the product.
            type: str
            returned: always
        msg:
            description: Why the parcel failed.
            type: str
            returned: always
        status_code:
            description: The HTTP status code of the Cloudera Manager error.
            type: int
            returned: when the failure was an API error
"""

import json

from concurrent.futures import ThreadPoolExecutor

from ansible.module_utils.common.text.converters import to_text

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.parcel_utils import (
    Parcel,
    ParcelException,
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
        self.parcels = self.get_param("parcels")
        self.max_workers = max(1, self.get_param("max_workers"))
        self.state = self.get_param("state")
        self.delay = self.get_param("delay")
        self.timeout = self.get_param("timeout")

        # Set outputs
        self.changed = False
        self.diff = {}
        self.output = {} if self.parcels is None else []

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

        # Normalize self.state
        if self.state == "present":
            self.state = "ACTIVATED"
        elif self.state == "absent":
            self.state = "AVAILABLE_REMOTELY"
        else:
            self.state = str(self.state).upper()

        if self.parcels is None:
            targets = [dict(name=self.parcel_name, parcel_version=self.parcel_version)]
        else:
            targets = self.parcels

        keys = [(t["name"], t["parcel_version"]) for t in targets]
        duplicates = sorted({f"{n} ({v})" for n, v in keys if keys.count((n, v)) > 1})
        if duplicates:
            self.module.fail_json(
                msg=f"Parcels must be unique; duplicated: {', '.join(duplicates)}",
            )

        # Resolve every parcel up front, so a typo fails the run before any download starts.
        parcels, missing = [], []
        for target in targets:
            try:
                parcels.append(
                    self._load(parcel_api, target["name"], target["parcel_version"]),
                )
            except ParcelException as ex:
                missing.append(str(ex))
        if missing:
            self.module.fail_json(msg="; ".join(missing))

        self.changed = any(p.stage != self.state for p in parcels)

        if self.parcels is None:
            self._process_single(parcel_api, parcels[0])
        else:
            self._process_parallel(parcel_api, parcels)

    def _load(self, parcel_api, name, version):
        try:
            return Parcel(
                parcel_api=parcel_api,
                product=name,
                version=version,
                cluster=self.cluster,
                log=self.module.log,
                delay=self.delay,
                timeout=self.timeout,
            )
        except ApiException as ex:
            if ex.status == 404:
                raise ParcelException(
                    f"Parcel {name} (version: {version}) not found on cluster '{self.cluster}'",
                )
            raise

    def _apply(self, parcel_api, parcel):
        """Move one parcel to the requested state and return its final details."""
        pending = not self.module.check_mode and parcel.stage != self.state

        if pending:
            getattr(parcel, self.FUNCTION_MAP[self.state])()

        result = parse_parcel_result(
            parcel_api.read_parcel(
                cluster_name=self.cluster,
                product=parcel.product,
                version=parcel.version,
            ),
        )

        if pending and result["stage"] != self.state:
            raise ParcelException(
                f"Parcel {parcel.product} (version: {parcel.version}) did not reach {self.state} "
                f"on cluster '{self.cluster}'; current stage is {result['stage']} (timeout: {self.timeout} secs)",
            )

        return result

    def _process_single(self, parcel_api, parcel):
        if self.changed and self.module._diff:
            self.diff = dict(before=parcel.stage, after=self.state)

        try:
            self.output = self._apply(parcel_api, parcel)
        except ParcelException as ex:
            self.module.fail_json(msg=str(ex))

    def _process_parallel(self, parcel_api, parcels):
        # Leaving the block waits for every parcel to finish, so one failure
        # never abandons commands that Cloudera Manager is still running.
        with ThreadPoolExecutor(
            max_workers=min(self.max_workers, max(1, len(parcels))),
            thread_name_prefix="parcel",
        ) as pool:
            futures = [pool.submit(self._apply, parcel_api, p) for p in parcels]

        if self.module._diff:
            changed = [p for p in parcels if p.stage != self.state]
            self.diff = dict(
                before={f"{p.product}-{p.version}": p.stage for p in changed},
                after={f"{p.product}-{p.version}": self.state for p in changed},
            )

        failures = []
        for parcel, future in zip(parcels, futures):
            try:
                self.output.append(future.result())
            except Exception as ex:
                failures.append(self._describe_failure(parcel, ex))

        if failures:
            self.module.fail_json(
                msg=f"Failed to move {len(failures)} of {len(parcels)} parcel(s) to {self.state}",
                changed=self.changed,
                failures=failures,
                parcels=self.output,
            )

    @staticmethod
    def _describe_failure(parcel, ex):
        failure = dict(product=parcel.product, version=parcel.version)

        if isinstance(ex, ApiException):
            failure.update(status_code=ex.status)
            msg = None
            if ex.body:
                try:
                    msg = json.loads(ex.body)["message"]
                except Exception:
                    pass
            failure.update(msg=msg or "API error: " + to_text(ex.reason))
        else:
            failure.update(msg=to_text(ex))

        return failure


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
            name=dict(aliases=["parcel", "product"]),
            parcel_version=dict(),
            parcels=dict(
                type="list",
                elements="dict",
                options=dict(
                    name=dict(required=True, aliases=["parcel", "product"]),
                    parcel_version=dict(required=True),
                ),
            ),
            max_workers=dict(type="int", default=4),
            delay=dict(
                required=False,
                type="int",
                default=15,
                aliases=["polling_interval"],
            ),
            timeout=dict(
                required=False,
                type="int",
                default=1200,
                aliases=["polling_timeout"],
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
        mutually_exclusive=[["parcels", "name"], ["parcels", "parcel_version"]],
        required_together=[["name", "parcel_version"]],
        required_one_of=[["parcels", "name"]],
        supports_check_mode=True,
    )

    result = ClouderaParcel(module)

    output = dict(changed=result.changed)

    if result.parcels is None:
        output.update(parcel=result.output)
    else:
        output.update(parcels=result.output)

    if module._diff:
        output.update(diff=result.diff)

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
