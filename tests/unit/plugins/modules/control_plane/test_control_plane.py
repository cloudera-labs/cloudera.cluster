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

import yaml

__metaclass__ = type

import logging
import os
import pytest
import unittest

from ansible_collections.cloudera.cluster.plugins.modules import control_plane
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def test_create_embedded_control_plane(module_args, conn):

    if os.getenv("CONTROL_PLANE_DATALAKE_NAME", None):
        conn.update(datalake_cluster_name=os.getenv("CONTROL_PLANE_DATALAKE_NAME"))

    if os.getenv("CONTROL_PLANE_NAME", None):
        conn.update(name=os.getenv("CONTROL_PLANE_NAME"))

    if os.getenv("CONTROL_PLANE_REMOTE_REPO_URL", None):
        conn.update(remote_repo_url=os.getenv("CONTROL_PLANE_REMOTE_REPO_URL"))
    else:
        conn.update(
            remote_repo_url="https://archive.cloudera.com/p/cdp-pvc-ds/1.5.5-h1",
        )

    values_yaml_args = """
    values_yaml:
        ContainerInfo:
            Mode: public
            CopyDocker: false
        Database:
            Mode: embedded
            EmbeddedDbStorage: 200
        Vault:
            Mode: embedded
            EmbeddedDbStorage: 20
    """
    conn.update(yaml.safe_load(values_yaml_args))

    module_args(
        {
            **conn,
            "state": "present",
            "type": "embedded",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        control_plane.main()

    # Verify basic response structure
    assert e.value.changed == False
    assert isinstance(e.value.control_plane, dict)


def test_remove_embedded_control_plane(module_args, conn):

    if os.getenv("CONTROL_PLANE_NAME", None):
        conn.update(name=os.getenv("CONTROL_PLANE_NAME"))

    module_args(
        {
            **conn,
            "state": "absent",
            "type": "embedded",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        control_plane.main()

    # Verify basic response structure
    assert e.value.changed == True
