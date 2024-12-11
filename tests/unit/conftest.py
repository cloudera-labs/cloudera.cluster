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

import json
import sys
import pytest
import yaml

from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

# # Required for pytest discovery in VSCode, reasons unknown...
# try:
#     from ansible.plugins.action import ActionBase
# except ModuleNotFoundError:
#     pass

from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleFailJson,
    AnsibleExitJson,
)


@pytest.fixture(autouse=True)
def skip_python():
    if sys.version_info < (3, 6):
        pytest.skip(
            "Skipping on Python %s. cloudera.cloud supports Python 3.6 and higher."
            % sys.version
        )


@pytest.fixture(autouse=True)
def patch_module(monkeypatch):
    """Patch AnsibleModule to raise exceptions on success and failure"""

    def exit_json(*args, **kwargs):
        if "changed" not in kwargs:
            kwargs["changed"] = False
        raise AnsibleExitJson(kwargs)

    def fail_json(*args, **kwargs):
        kwargs["failed"] = True
        raise AnsibleFailJson(kwargs)

    monkeypatch.setattr(basic.AnsibleModule, "exit_json", exit_json)
    monkeypatch.setattr(basic.AnsibleModule, "fail_json", fail_json)


@pytest.fixture
def module_args():
    """Prepare module arguments"""

    def prep_args(args=dict()):
        args = json.dumps({"ANSIBLE_MODULE_ARGS": args})
        basic._ANSIBLE_ARGS = to_bytes(args)

    return prep_args


@pytest.fixture
def yaml_args():
    """Prepare module arguments from YAML"""

    def prep_args(args: str = ""):
        output = json.dumps({"ANSIBLE_MODULE_ARGS": yaml.safe_load(args)})
        basic._ANSIBLE_ARGS = to_bytes(output)

    return prep_args


# class AnsibleExitJson(Exception):
#     """Exception class to be raised by module.exit_json and caught by the test case"""

#     def __init__(self, kwargs):
#         super(AnsibleExitJson, self).__init__(
#             kwargs.get("msg", "General module success")
#         )
#         self.__dict__.update(kwargs)


# class AnsibleFailJson(Exception):
#     """Exception class to be raised by module.fail_json and caught by the test case"""

#     def __init__(self, kwargs):
#         super(AnsibleFailJson, self).__init__(
#             kwargs.get("msg", "General module failure")
#         )
#         self.__dict__.update(kwargs)
