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

import logging
import os
import pytest

from ansible_collections.cloudera.cluster.plugins.modules import (
    service_role_config_info,
)
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)

# Skip all tests due to pending removal of module from collection
pytestmark = pytest.mark.skip("Deprecated module")


@pytest.fixture()
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


def test_missing_required(conn, module_args):
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster, service"):
        service_role_config_info.main()


def test_missing_service(conn, module_args):
    conn.update(service="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster"):
        service_role_config_info.main()


def test_missing_cluster(conn, module_args):
    conn.update(cluster="example")
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="service"):
        service_role_config_info.main()


def test_view_default(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": os.getenv("CM_CLUSTER"),
            "service": os.getenv("CM_SERVICE"),
            "role": os.getenv("CM_ROLE"),
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_role_config_info.main()

    assert len(e.value.config) > 0


def test_invalid_service(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": os.getenv("CM_CLUSTER"),
            "service": "BOOM",
            "role": os.getenv("CM_ROLE"),
        }
    )

    with pytest.raises(AnsibleFailJson, match="Service does not exist: BOOM"):
        service_role_config_info.main()


def test_invalid_cluster(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": "BOOM",
            "service": os.getenv("CM_SERVICE"),
            "role": os.getenv("CM_ROLE"),
        }
    )

    with pytest.raises(AnsibleFailJson, match="Cluster does not exist: BOOM"):
        service_role_config_info.main()
