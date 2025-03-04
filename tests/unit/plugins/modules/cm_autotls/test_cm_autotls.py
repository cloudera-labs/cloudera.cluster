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
import os
import logging
import pytest

from ansible_collections.cloudera.cluster.plugins.modules import cm_autotls
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


def test_pytest_enable_auto_tls(module_args, conn):

    if os.getenv("AUTOTLS_CXN_USER", None):
        conn.update(connection_user_name=os.getenv("AUTOTLS_CXN_USER"))

    if os.getenv("AUTOTLS_CXN_SSH_PRIVATE_KEY_FILE", None):
        with open(os.getenv("AUTOTLS_CXN_SSH_PRIVATE_KEY_FILE")) as f:
            conn.update(connection_private_key=f.read())

    if os.getenv("AUTOTLS_CXN_SSH_PASSWORD", None):
        conn.update(connection_password=os.getenv("AUTOTLS_CXN_SSH_PASSWORD"))

    module_args({**conn, "state": "present"})

    with pytest.raises(AnsibleExitJson) as e:
        cm_autotls.main()

    assert e.value.changed == True


def test_enable_invalid_ssh(module_args, conn):

    if os.getenv("AUTOTLS_CXN_USER", None):
        conn.update(connection_user_name=os.getenv("AUTOTLS_CXN_USER"))

    if os.getenv("AUTOTLS_CXN_SSH_PRIVATE_KEY_FILE", None):
        with open(os.getenv("AUTOTLS_CXN_SSH_PRIVATE_KEY_FILE")) as f:
            conn.update(connection_private_key=f.read())

    if os.getenv("AUTOTLS_CXN_SSH_PASSWORD", None):
        conn.update(connection_password=os.getenv("AUTOTLS_CXN_SSH_PASSWORD"))

    # Ensure TLS is disabled if not already
    module_args({**conn, "force": True, "state": "absent"})

    with pytest.raises(AnsibleExitJson) as e:
        cm_autotls.main()

    # Update parameters to enable with invalid ssh key
    module_args(
        {**conn, "connection_private_key": "invalid-ssh-key", "state": "present"}
    )

    with pytest.raises(AnsibleFailJson, match="Could not authenticate"):
        cm_autotls.main()


def test_force_enable_auto_tls(module_args, conn):

    if os.getenv("AUTOTLS_CXN_USER", None):
        conn.update(connection_user_name=os.getenv("AUTOTLS_CXN_USER"))

    if os.getenv("AUTOTLS_CXN_SSH_PRIVATE_KEY_FILE", None):
        with open(os.getenv("AUTOTLS_CXN_SSH_PRIVATE_KEY_FILE")) as f:
            conn.update(connection_private_key=f.read())

    if os.getenv("AUTOTLS_CXN_SSH_PASSWORD", None):
        conn.update(connection_password=os.getenv("AUTOTLS_CXN_SSH_PASSWORD"))

    # Ensure TLS is enabled with all args
    module_args({**conn, "state": "present"})

    with pytest.raises(AnsibleExitJson) as e:
        cm_autotls.main()

    # Add force enable
    module_args({**conn, "force": True, "state": "present"})

    with pytest.raises(AnsibleExitJson) as e:
        cm_autotls.main()

    assert e.value.changed == True


def test_pytest_disable_auto_tls(module_args, conn):

    module_args({**conn, "state": "absent"})

    with pytest.raises(AnsibleExitJson) as e:
        cm_autotls.main()
