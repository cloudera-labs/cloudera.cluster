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

from ansible_collections.cloudera.cluster.plugins.modules import cm_config
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def test_missing_parameters(conn, module_args):
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="config"):
        cm_config.main()




def test_set_config(conn, module_args):
    module_args({
        **conn,
        "parameters": dict(custom_header_color="PURPLE"),
    })

    with pytest.raises(AnsibleExitJson) as e:
        cm_config.main()

    assert e.value.changed == True
    assert len(e.value.config) > 0

    with pytest.raises(AnsibleExitJson) as e:
        cm_config.main()

    assert e.value.changed == False
    assert len(e.value.config) > 0


def test_unset_config(conn, module_args):
    module_args({
        **conn, 
        "parameters": dict(custom_header_color=None)
    })

    with pytest.raises(AnsibleExitJson) as e:
        cm_config.main()

    assert e.value.changed == True
    assert len(e.value.config) > 0

    with pytest.raises(AnsibleExitJson) as e:
        cm_config.main()

    assert e.value.changed == False
    assert len(e.value.config) > 0


def test_set_config_with_purge(conn, module_args):
    module_args({
        **conn,
        "params": dict(custom_header_color="PURPLE"),
        "purge": True,
    })

    with pytest.raises(AnsibleExitJson) as e:
        cm_config.main()

    assert e.value.changed == True
    assert len(e.value.config) > 1

    with pytest.raises(AnsibleExitJson) as e:
        cm_config.main()

    assert e.value.changed == False
    assert len(e.value.config) > 1


def test_purge_all_config(conn, module_args):
    module_args({
        **conn,
        "params": dict(),
        "purge": True,
    })

    with pytest.raises(AnsibleExitJson) as e:
        cm_config.main()

    assert e.value.changed == True
    assert len(e.value.config) > 1

    with pytest.raises(AnsibleExitJson) as e:
        cm_config.main()

    assert e.value.changed == False
    assert len(e.value.config) > 1
