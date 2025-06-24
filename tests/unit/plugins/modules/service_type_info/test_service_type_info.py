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
import pytest

from ansible_collections.cloudera.cluster.plugins.modules import service_type_info
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def test_missing_required(conn, module_args):
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="cluster"):
        service_type_info.main()


def test_invalid_cluster(conn, module_args):
    module_args(
        {
            **conn,
            "cluster": "BOOM",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_type_info.main()

    assert len(e.value.service_types) == 0


def test_view_all_services_types(conn, module_args, base_cluster):
    module_args(
        {
            **conn,
            "cluster": base_cluster.name,
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        service_type_info.main()

    assert len(e.value.service_types) > 0
