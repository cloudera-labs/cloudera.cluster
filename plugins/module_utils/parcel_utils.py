# Copyright 2024 Cloudera, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A common functions for Cloudera Manager parcel management
"""

import time

from enum import IntEnum

from cm_client import ParcelResourceApi


class Parcel(object):

    STAGE = IntEnum(
        "STAGE",
        "AVAILABLE_REMOTELY DOWNLOADING DOWNLOADED UNDISTRIBUTING DISTRIBUTING DISTRIBUTED ACTIVATING ACTIVATED",
    )

    def __init__(
        self,
        parcel_api: ParcelResourceApi,
        product: str,
        version: str,
        cluster: str,
        delay: int = 15,
        timeout: int = 600,
    ) -> None:
        self.parcel_api = parcel_api
        self.product = product
        self.version = version
        self.cluster = cluster
        self.delay = delay
        self.timeout = timeout

        self.current = Parcel.STAGE[
            str(
                self.parcel_api.read_parcel(
                    cluster_name=self.cluster,
                    product=self.product,
                    version=self.version,
                ).stage
            ).upper()
        ]

    @property
    def stage(self) -> str:
        return self.current.name

    def _wait(self, stage: STAGE) -> None:
        end_time = time.time() + self.timeout

        while end_time > time.time():
            parcel_status = self.parcel_api.read_parcel(
                cluster_name=self.cluster, product=self.product, version=self.version
            )
            if parcel_status.stage == stage.name:
                return
            else:
                time.sleep(self.delay)

        return Exception(f"Failed to reach {stage.name}: timeout ({self.timeout} secs)")

    def _exec(self, stage: STAGE, func) -> None:
        func(
            cluster_name=self.cluster,
            product=self.product,
            version=self.version,
        )
        self._wait(stage)

    def remove(self):
        if self.current > self.STAGE.AVAILABLE_REMOTELY:
            self.download(self.STAGE.AVAILABLE_REMOTELY)
            self._exec(
                self.STAGE.AVAILABLE_REMOTELY, self.parcel_api.remove_download_command
            )

    def download(self, target: STAGE = STAGE.DOWNLOADED):
        if self.current > target:
            self.distribute(target)
            self._exec(
                self.STAGE.DOWNLOADED,
                self.parcel_api.start_removal_of_distribution_command,
            )
        elif self.current == self.STAGE.DOWNLOADING:
            self._wait(self.STAGE.DOWNLOADED)
        elif self.current < self.STAGE.DOWNLOADING:
            self._exec(self.STAGE.DOWNLOADED, self.parcel_api.start_download_command)

    def distribute(self, target: STAGE = STAGE.DISTRIBUTED):
        if self.current > target:
            self._exec(self.STAGE.DISTRIBUTED, self.parcel_api.deactivate_command)
        elif self.current == self.STAGE.DISTRIBUTING:
            self._wait(self.STAGE.DISTRIBUTED)
        elif self.current < self.STAGE.DISTRIBUTING:
            self.download(target)
            self._exec(
                self.STAGE.DISTRIBUTED, self.parcel_api.start_distribution_command
            )

    def activate(self):
        if self.current == self.STAGE.ACTIVATING:
            self._wait(self.STAGE.ACTIVATED)
        elif self.current < self.STAGE.ACTIVATED:
            self.distribute(self.STAGE.ACTIVATED)
            self._exec(self.STAGE.ACTIVATED, self.parcel_api.activate_command)
