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
import unittest

from ansible_collections.cloudera.cluster.plugins.modules import cm_resource
from ansible_collections.cloudera.cluster.tests.unit.plugins.modules.utils import AnsibleExitJson, AnsibleFailJson, ModuleTestCase, setup_module_args


@unittest.skipUnless(os.getenv('CM_USERNAME'), "Cloudera Manager access parameters not set")
class TestCMResourceIntegration(ModuleTestCase):
    
    def test_post(self):
        create_module_args = {
            "username": os.getenv('CM_USERNAME'),
            "password": os.getenv('CM_PASSWORD'),
            "host": os.getenv('CM_HOST'),
            "verify_tls": "no",
            "debug": "yes",
            "method": "POST",
            "path": "/users",
            "body": {
                "items": [
                    {
                        "name": "unit_test",
                        "password": "UnsecurePassword"
                    }
                ]
            }
        }
        
        update_module_args = {
            "username": os.getenv('CM_USERNAME'),
            "password": os.getenv('CM_PASSWORD'),
            "host": os.getenv('CM_HOST'),
            "verify_tls": "no",
            "debug": "yes",
            "method": "PUT",
            "path": "/users/unit_test",
            "body": {
                "authRoles": [{ "name": "ROLE_LIMITED" }]
            }
        }
        
        delete_module_args = {
            "username": os.getenv('CM_USERNAME'),
            "password": os.getenv('CM_PASSWORD'),
            "host": os.getenv('CM_HOST'),
            "verify_tls": "no",
            "debug": "yes",
            "method": "DELETE",
            "path": "/users/unit_test"
        }
        
        # Create
        setup_module_args(create_module_args)
        with pytest.raises(AnsibleExitJson) as e:
            cm_resource.main()
        self.assertIsInstance(e.value.args[0]['resources'], list)
        
        # Create fail on duplicate
        setup_module_args(create_module_args)
        with pytest.raises(AnsibleFailJson) as e:
            cm_resource.main()
        self.assertEquals(e.value.args[0]['status_code'], 400)
        
        # Update
        setup_module_args(update_module_args)
        with pytest.raises(AnsibleExitJson) as e:
            cm_resource.main()
        self.assertIsInstance(e.value.args[0]['resources'], list)
        
        # Delete
        setup_module_args(delete_module_args)
        with pytest.raises(AnsibleExitJson) as e:
            cm_resource.main()
        self.assertIsInstance(e.value.args[0]['resources'], list)
        
        # Delete fail on existence
        setup_module_args(delete_module_args)
        with pytest.raises(AnsibleFailJson) as e:
            cm_resource.main()
        self.assertEquals(e.value.args[0]['status_code'], 404)
        

if __name__ == '__main__':
    unittest.main()