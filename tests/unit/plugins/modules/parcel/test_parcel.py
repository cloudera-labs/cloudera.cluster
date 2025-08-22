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

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import logging
import pytest

from ansible_collections.cloudera.cluster.plugins.modules import parcel
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
        parcel="test",
        parcel_version="test",
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="Cluster 'BOOM' not found"):
        parcel.main()


def test_pytest_download_parcel(conn, module_args):
    conn.update(
        cluster_name=os.getenv("CM_CLUSTER"),
        parcel_name=os.getenv("CM_PARCEL_NAME"),
        parcel_version=os.getenv("CM_PARCEL_VERSION"),
        state="downloaded",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        parcel.main()

    LOG.info(str(e.value.parcel))


def test_pytest_distribute_parcel(conn, module_args):
    conn.update(
        cluster_name=os.getenv("CM_CLUSTER"),
        parcel_name=os.getenv("CM_PARCEL_NAME"),
        parcel_version=os.getenv("CM_PARCEL_VERSION"),
        state="distributed",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        parcel.main()

    LOG.info(str(e.value.parcel))


def test_pytest_activate_parcel(conn, module_args):
    conn.update(
        cluster_name=os.getenv("CM_CLUSTER"),
        parcel_name=os.getenv("CM_PARCEL_NAME"),
        parcel_version=os.getenv("CM_PARCEL_VERSION"),
        state="activated",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        parcel.main()

    LOG.info(str(e.value.parcel))


def test_pytest_deactivate_parcel(conn, module_args):
    conn.update(
        cluster_name="Example_Base_Host_Host_Template_Assignment",  # os.getenv("CM_CLUSTER"),
        parcel_name="SPARK3",
        parcel_version="3.3.0.3.3.7180.0-274-1.p0.31212967",
        state="distributed",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        parcel.main()

    LOG.info(str(e.value.parcel))


def test_pytest_undistribute_parcel(conn, module_args):
    conn.update(
        cluster_name=os.getenv("CM_CLUSTER"),
        parcel_name=os.getenv("CM_PARCEL_NAME"),
        parcel_version=os.getenv("CM_PARCEL_VERSION"),
        state="downloaded",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        parcel.main()

    LOG.info(str(e.value.parcel))


def test_pytest_remove_parcel(conn, module_args):
    conn.update(
        cluster_name=os.getenv("CM_CLUSTER"),
        parcel_name=os.getenv("CM_PARCEL_NAME"),
        parcel_version=os.getenv("CM_PARCEL_VERSION"),
        state="absent",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        parcel.main()

    LOG.info(str(e.value.parcel))
