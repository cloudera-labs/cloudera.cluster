# -*- coding: utf-8 -*-

# Copyright 2023 Cloudera, Inc. All Rights Reserved.
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

from ansible_collections.cloudera.cluster.plugins.modules import cm_config_info
from ansible_collections.cloudera.cluster.tests.unit import AnsibleExitJson, AnsibleFailJson

LOG = logging.getLogger(__name__)


@pytest.fixture()
def conn():
    return {
        "username": os.getenv('CM_USERNAME'),
        "password": os.getenv('CM_PASSWORD'),
        "host": os.getenv('CM_HOST'),
        "port": "7180",
        "verify_tls": "no",
        "debug": "yes",
    }

def test_get_cluster_config(conn, module_args):
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cm_config_info.main()

    assert len(e.value.config) > 0

def test_get_cluster_config_full(conn, module_args):
    module_args({
        **conn,
        "view": "full"
    })

    with pytest.raises(AnsibleExitJson) as e:
        cm_config_info.main()

    assert len(e.value.config) > 0
