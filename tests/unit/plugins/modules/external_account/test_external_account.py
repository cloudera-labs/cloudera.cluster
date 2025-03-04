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

from ansible_collections.cloudera.cluster.plugins.modules import external_account
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




def test_create_aws_keys(module_args, conn):
    conn.update(
        name="aws_test_key",
        category="AWS",
        type="AWS_ACCESS_KEY_AUTH",
        params={
            "aws_access_key": "access_key1",
            "aws_secret_key": "secret_key11",
        },
        state="present",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        external_account.main()

    LOG.info(str(e.value.external_account_output))


def test_create_aws_role(module_args, conn):
    conn.update(
        name="aws_test_role",
        category="AWS",
        type="AWS_IAM_ROLES_AUTH",
        state="present",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        external_account.main()

    LOG.info(str(e.value.external_account_output))


def test_create_azure_credentials(module_args, conn):
    conn.update(
        name="azure_test",
        category = 'AZURE',
        type="ADLS_AD_SVC_PRINC_AUTH",
        params={
            "adls_client_id": "Client_test",
            "adls_client_key": "Secret_test",
            "adls_tenant_id": "Tenant_test",
        },
        state="present",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        external_account.main()

    LOG.info(str(e.value.external_account_output))


def test_create_external_basic_user(module_args, conn):
    conn.update(
        name="John",
        category = 'BASICAUTH',
        type="BASIC_AUTH",
        params={"username": "John", "password": "123456"},
        state="present",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        external_account.main()

    LOG.info(str(e.value.external_account_output))

def test_update_aws_keys(module_args, conn):
    conn.update(
        name="aws_test_key",
        category="AWS",
        type="AWS_ACCESS_KEY_AUTH",
        params={
            "aws_access_key": "AAAAAA22",
            "aws_secret_key": "22222222",
        },
        state="present",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        external_account.main()

    LOG.info(str(e.value.external_account_output))

def test_update_external_basic_user(module_args, conn):
    conn.update(
        name="John",
        category = 'BASICAUTH',
        type="BASIC_AUTH",
        params={"username": "John01", "password": "AAAAA"},
        state="present",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        external_account.main()

    LOG.info(str(e.value.external_account_output))

def test_remove_external_basic_user(module_args, conn):
    conn.update(
        name="John",
        state="absent",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        external_account.main()

    LOG.info(str(e.value.external_account_output))
