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
import os
import pytest
import unittest

from ansible_collections.cloudera.cluster.plugins.modules import control_plane_info
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def test_list_all_control_planes_simple(module_args, conn):

    module_args({**conn})

    with pytest.raises(AnsibleExitJson) as e:
        control_plane_info.main()

    # Verify basic response structure
    assert e.value.changed == False
    assert isinstance(e.value.control_planes, list)

    # Log the results for debugging
    LOG.info(f"Found {len(e.value.control_planes)} control planes")


def test_invalid_credentials(module_args, conn):
    """Test behavior with invalid credentials"""

    # Update parameters to enable with invalid ssh key
    conn.update(username="invalid_user", password="invalid_pass")
    module_args({**conn})

    with pytest.raises(AnsibleFailJson) as e:
        control_plane_info.main()

    # Should fail with authentication error
    assert e.value.failed == True
