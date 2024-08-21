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

from ansible_collections.cloudera.cluster.plugins.modules import external_user_mappings
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
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


def test_create_admin_external_mapping(module_args, conn):
    conn.update(
        name="admin_mapping",
        type="LDAP",
        auth_roles=["ROLE_CLUSTER_ADMIN"],
    )

    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        external_user_mappings.main()

    LOG.info(str(e.value.external_user_mappings_output))


def test_delete_admin_external_mapping(module_args, conn):
    conn.update(
        name="admin_mapping",
        type="LDAP",
        state="absent",
    )

    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        external_user_mappings.main()

    LOG.info(str(e.value.external_user_mappings_output))


def test_create_default_user_external_mapping(module_args, conn):
    conn.update(
        name="user_mapping",
        type="LDAP",
        auth_roles=["ROLE_DASHBOARD_USER", "ROLE_USER"],
    )

    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        external_user_mappings.main()

    LOG.info(str(e.value.external_user_mappings_output))


def test_upgrade_default_user_external_mapping(module_args, conn):
    conn.update(
        name="user_mapping",
        type="LDAP",
        auth_roles=["ROLE_CLUSTER_ADMIN"],
    )

    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        external_user_mappings.main()

    LOG.info(str(e.value.external_user_mappings_output))


def test_configure_new_auth_roles_on_existing_user(module_args, conn):
    conn.update(
        name="user_mapping",
        type="LDAP",
        auth_roles=["ROLE_CLUSTER_ADMIN"],
        purge=True,
    )

    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        external_user_mappings.main()

    LOG.info(str(e.value.external_user_mappings_output))
