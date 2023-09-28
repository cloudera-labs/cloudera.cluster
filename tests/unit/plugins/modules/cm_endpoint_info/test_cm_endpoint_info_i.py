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

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import pytest
import re
import unittest

from ansible_collections.cloudera.cluster.plugins.modules import cm_endpoint_info
from ansible_collections.cloudera.cluster.tests.unit.plugins.modules.utils import AnsibleExitJson, AnsibleFailJson, ModuleTestCase, setup_module_args


@unittest.skipUnless(os.getenv('CM_USERNAME'), "Cloudera Manager access parameters not set")
class TestCMVersionIntegration(ModuleTestCase):
    
    def test_host_discovery(self):
        setup_module_args({
            "username": os.getenv('CM_USERNAME'),
            "password": os.getenv('CM_PASSWORD'),
            "host": os.getenv('CM_HOST'),
            "port": "7180",
            "verify_tls": "no",
            "debug": "yes"
        })
        
        with pytest.raises(AnsibleExitJson) as e:
            cm_endpoint_info.main()
            
        self.assertEquals(e.value.args[0]['endpoint'], "https://" + os.getenv('CM_HOST') + ":" + os.getenv('CM_PORT_TLS') + "/api/" + os.getenv('CM_VERSION'))
        
    def test_direct_endpoint(self):
        setup_module_args({
            "username": os.getenv('CM_USERNAME'),
            "password": os.getenv('CM_PASSWORD'),
            "url": "http://not.supported",
            "verify_tls": "no",
            "debug": "yes"
        })
        
        with pytest.raises(AnsibleFailJson) as e:
            cm_endpoint_info.main()
            
        self.assertRegexpMatches(e.value.args[0]['msg'], "^Unsupported parameters")


if __name__ == '__main__':
    unittest.main()