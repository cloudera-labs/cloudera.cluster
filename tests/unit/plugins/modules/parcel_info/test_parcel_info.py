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

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import logging
import pytest

from ansible_collections.cloudera.cluster.plugins.modules import parcel_info
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


@pytest.fixture
def conn():
    conn = dict(username=os.getenv("CM_USERNAME"), password=os.getenv("CM_PASSWORD"))

    if os.getenv("CM_HOST", None):
        conn.update(host=os.getenv("CM_HOST"))

    if os.getenv("CM_PORT", None):
        conn.update(port=os.getenv("CM_PORT"))

    if os.getenv("CM_ENDPOINT", None):
        conn.update(url=os.getenv("CM_ENDPOINT"))

    if os.getenv("CM_PROXY", None):
        conn.update(proxy=os.getenv("CM_PROXY"))

    return {
        **conn,
        "verify_tls": "no",
        "debug": "no",
    }


def test_invalid_cluster(module_args, conn):
    conn.update(
        cluster_name="BOOM",
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="Cluster 'BOOM' not found"):
        parcel_info.main()


def test_single_parcel(module_args, conn):
    conn.update(
        cluster_name=os.getenv("CM_CLUSTER"),
        product="CDH",
        parcel_version="7.1.9-1.cdh7.1.9.p0.44702451",
    )

    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        parcel_info.main()

    LOG.info(str(e.value.parcels))

    assert len(e.value.parcels) == 1


def test_missing_parcel(module_args, conn):
    conn.update(
        cluster_name=os.getenv("CM_CLUSTER"),
        product="BOOM",
        parcel_version="1.2.3",
    )

    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        parcel_info.main()

    LOG.info(str(e.value.parcels))

    assert len(e.value.parcels) == 0


def test_all_parcels(module_args, conn):
    conn.update(
        cluster_name=os.getenv("CM_CLUSTER"),
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        parcel_info.main()

    LOG.info(str(e.value.parcels))

    assert len(e.value.parcels) > 1
