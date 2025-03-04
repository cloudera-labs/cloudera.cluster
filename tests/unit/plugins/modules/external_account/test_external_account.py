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

from __future__ import absolute_import, division, print_function

__metaclass__ = type
import logging
import pytest

from ansible_collections.cloudera.cluster.plugins.modules import external_account
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def test_create_aws_keys(module_args, conn, request):
    module_args(
        {
            **conn,
            "name": "aws_test_key55",
            "category": "AWS",
            "type": "AWS_ACCESS_KEY_AUTH",
            "params": {
                "aws_access_key": "access_key1",
                "aws_secret_key": "secret_key11",
            },
            "state": "present",
        }
    )
    with pytest.raises(AnsibleExitJson) as e:
        external_account.main()

    assert e.value.changed == True
    LOG.info(str(e.value.external_account))

def test_create_aws_role(module_args, conn, request):
    module_args(
        {
            **conn,
            "name": "aws_test_role",
            "category": "AWS",
            "type": "AWS_IAM_ROLES_AUTH",
            "state": "present",
        }
    )
    with pytest.raises(AnsibleExitJson) as e:
        external_account.main()

    assert e.value.changed == True
    LOG.info(str(e.value.external_account))


def test_create_azure_credentials(module_args, conn, request):
    module_args(
        {
            **conn,
            "name": "azure_test",
            "category": "AZURE",
            "type": "ADLS_AD_SVC_PRINC_AUTH",
            "params": {
                "adls_client_id": "Client_test",
                "adls_client_key": "secret_key11",
                "adls_tenant_id": "Tenant_test",
            },
            "state": "present",
        }
    )
    with pytest.raises(AnsibleExitJson) as e:
        external_account.main()

    assert e.value.changed == True
    LOG.info(str(e.value.external_account))



def test_create_external_basic_user(module_args, conn, request):
    module_args(
        {
            **conn,
            "name": "John",
            "category": "BASICAUTH",
            "type": "BASIC_AUTH",
            "params": {
                "username": "John",
                "password": "123456",
            },
            "state": "present",
        }
    )
    with pytest.raises(AnsibleExitJson) as e:
        external_account.main()

    assert e.value.changed == True
    LOG.info(str(e.value.external_account))


def test_update_aws_keys_diff_enabled(module_args, conn, request):
    module_args(
        {
            **conn,
            "name": "aws_test_key55",
            "category": "AWS",
            "type": "AWS_ACCESS_KEY_AUTH",
            "params": {
                "aws_access_key": "AAAAAA22",
                "aws_secret_key": "22222222",
            },
            "state": "present",
            "_ansible_diff": True,

        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        external_account.main()

    assert e.value.changed == True
    LOG.info(str(e.value.external_account))


def test_update_aws_keys(module_args, conn, request):
    module_args(
        {
            **conn,
            "name": "aws_test_key55",
            "category": "AWS",
            "type": "AWS_ACCESS_KEY_AUTH",
            "params": {
                "aws_access_key": "AAAAAA22",
                "aws_secret_key": "22222222",
            },
            "state": "present",

        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        external_account.main()

    assert e.value.changed == True
    LOG.info(str(e.value.external_account))



def test_remove_external_basic_user(module_args, conn, request):
    module_args(
        {
            **conn,
            "name": "John",
            "state": "absent",
        }
    )
    with pytest.raises(AnsibleExitJson) as e:
        external_account.main()

    assert e.value.changed == True
    LOG.info(str(e.value.external_account))

