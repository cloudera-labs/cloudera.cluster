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

from ansible_collections.cloudera.cluster.plugins.modules import cm_endpoint_info
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

from cm_client.rest import RESTClientObject
from urllib3.response import HTTPResponse

LOG = logging.getLogger(__name__)


def test_host_discovery(module_args, monkeypatch):
    spec = {
        "username": "testuser",
        "password": "testpassword",
        "host": "test.cldr.info",
        "port": "7180",
        "verify_tls": "no",
        "debug": "yes",
    }

    def response():
        return HTTPResponse()

    monkeypatch.setattr("urllib3.HTTPConnectionPool.urlopen", response)

    module_args(spec)

    with pytest.raises(AnsibleExitJson) as e:
        cm_endpoint_info.main()

    assert e.value.endpoint == f"https://{spec['host']}:7183/api/v01"
