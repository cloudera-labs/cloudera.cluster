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

from ansible_collections.cloudera.cluster.plugins.modules import external_account_info
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def test_get_spcific_aws_type(module_args, conn):
    module_args({**conn, "type": "AWS_ACCESS_KEY_AUTH"})

    with pytest.raises(AnsibleExitJson) as e:
        external_account_info.main()

    assert e.value.changed == False
    LOG.info(str(e.value.external_accounts))


def test_list_all_external_accounts(module_args, conn):
    module_args({**conn})

    with pytest.raises(AnsibleExitJson) as e:
        external_account_info.main()

    assert e.value.changed == False
    LOG.info(str(e.value.external_accounts))


def test_get_specific_aws_account(module_args, conn):
    module_args({**conn, "name": "aws_test_key"})

    with pytest.raises(AnsibleExitJson) as e:
        external_account_info.main()

    assert e.value.changed == False
    LOG.info(str(e.value.external_accounts))
