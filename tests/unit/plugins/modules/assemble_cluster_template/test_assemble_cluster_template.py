# Copyright 2024 Cloudera, Inc.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import logging
import pytest

from ansible_collections.cloudera.cluster.plugins.modules import assemble_cluster_template
from ansible_collections.cloudera.cluster.tests.unit import AnsibleExitJson, AnsibleFailJson

LOG = logging.getLogger(__name__)
TEST_DIR = os.path.dirname(os.path.abspath(__file__))

def test_missing_required(module_args):
    module_args()

    with pytest.raises(AnsibleFailJson, match="dest, src"):
        assemble_cluster_template.main()
        
def test_missing_dest(module_args):
    module_args({
      "src": "foo.json"
    })

    with pytest.raises(AnsibleFailJson, match="dest"):
        assemble_cluster_template.main()

def test_missing_src(module_args):
    module_args({
      "dest": "foo.json"
    })

    with pytest.raises(AnsibleFailJson, match="src"):
        assemble_cluster_template.main()

def test_src_not_directory(module_args):
    module_args({
      "dest": "foo.json",
      "src": os.path.join(TEST_DIR, "invalid_src.json"),
    })

    with pytest.raises(AnsibleFailJson, match="not a directory"):
        assemble_cluster_template.main()

def test_merge_idempotent_key(module_args, tmp_path):
    module_args({
      "dest": os.path.join(tmp_path, "output.json"),
      "src": os.path.join(TEST_DIR, "fragments"),
    })

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()
