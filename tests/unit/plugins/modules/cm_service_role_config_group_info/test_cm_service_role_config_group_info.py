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


from ansible_collections.cloudera.cluster.plugins.modules import (
    cm_service_role_config_group_info,
)
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def test_read_role_config_groups(conn, module_args, cms_auto):
    module_args({**conn})

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config_group_info.main()

    assert e.value.changed == False
    assert (
        len(e.value.role_config_groups) == 9
    )  # Gets all the base RCGs for all potential CM service roles


def test_read_role_config_group(conn, module_args, cms_auto):
    module_args(
        {
            **conn,
            "type": "HOSTMONITOR",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config_group_info.main()

    assert e.value.changed == False
    assert len(e.value.role_config_groups) == 1


def test_read_role_config_group_nonexistent(conn, module_args, cms_auto):
    module_args(
        {
            **conn,
            "type": "DOESNOTEXIST",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_service_role_config_group_info.main()

    assert len(e.value.role_config_groups) == 0


def test_read_service_nonexistent(conn, module_args):
    module_args({**conn})

    with pytest.raises(
        AnsibleFailJson,
        match="Cloudera Management service does not exist",
    ) as e:
        cm_service_role_config_group_info.main()
