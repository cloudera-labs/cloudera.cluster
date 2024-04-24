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
import os
import logging
import pytest

from ansible_collections.cloudera.cluster.plugins.modules import parcel
from ansible_collections.cloudera.cluster.tests.unit import AnsibleExitJson, AnsibleFailJson

LOG = logging.getLogger(__name__)



def test_pytest_download_parcel(module_args):
    module_args(
        {
            "username": os.getenv('CM_USERNAME'),
            "password": os.getenv('CM_PASSWORD'),
            "host": os.getenv('CM_HOST'),
            "cluster_name": "Base_Edge2AI_Node",
            "product": "ECS",
            "parcel_version": "1.5.1-b626-ecs-1.5.1-b626.p0.42068229",
            "state": "downloaded"
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        parcel.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))

def test_pytest_distribute_parcel(module_args):
    module_args(
        {
            "username": os.getenv('CM_USERNAME'),
            "password": os.getenv('CM_PASSWORD'),
            "host": os.getenv('CM_HOST'),
            "cluster_name": "Base_Edge2AI_Node",
            "product": "ECS",
            "parcel_version": "1.5.1-b626-ecs-1.5.1-b626.p0.42068229",
            "state": "distributed"
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        parcel.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))

def test_pytest_activate_parcel(module_args):
    module_args(
        {
            "username": os.getenv('CM_USERNAME'),
            "password": os.getenv('CM_PASSWORD'),
            "host": os.getenv('CM_HOST'),
            "cluster_name": "Base_Edge2AI_Node",
            "product": "ECS",
            "parcel_version": "1.5.1-b626-ecs-1.5.1-b626.p0.42068229",
            "state": "activated"
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        parcel.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))

def test_pytest_remove_parcel(module_args):
    module_args(
        {
            "username": os.getenv('CM_USERNAME'),
            "password": os.getenv('CM_PASSWORD'),
            "host": os.getenv('CM_HOST'),
            "cluster_name": "Base_Edge2AI_Node",
            "product": "ECS",
            "parcel_version": "1.5.1-b626-ecs-1.5.1-b626.p0.42068229",
            "state": "removed"
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        parcel.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))

def test_pytest_undistribute_parcel(module_args):
    module_args(
        {
            "username": os.getenv('CM_USERNAME'),
            "password": os.getenv('CM_PASSWORD'),
            "host": os.getenv('CM_HOST'),
            "cluster_name": "Base_Edge2AI_Node",
            "product": "ECS",
            "parcel_version": "1.5.1-b626-ecs-1.5.1-b626.p0.42068229",
            "state": "undistributed"
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        parcel.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))


def test_pytest_deactivate_parcel(module_args):
    module_args(
        {
            "username": os.getenv('CM_USERNAME'),
            "password": os.getenv('CM_PASSWORD'),
            "host": os.getenv('CM_HOST'),
            "cluster_name": "Base_Edge2AI_Node",
            "product": "ECS",
            "parcel_version": "1.5.1-b626-ecs-1.5.1-b626.p0.42068229",
            "state": "deactivated"
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        parcel.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))

