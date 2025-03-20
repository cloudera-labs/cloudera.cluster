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

from pathlib import Path

from ansible_collections.cloudera.cluster.plugins.modules import cm_kerberos
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)

def test_pytest_enable_kerberos(module_args, conn, request):
    
    if os.getenv("KDC_ADMIN_USER", None):
        conn.update(kdc_admin_user=os.getenv("KDC_ADMIN_USER"))

    if os.getenv("KDC_ADMIN_PASSWORD", None):
        conn.update(kdc_admin_password=os.getenv("KDC_ADMIN_PASSWORD"))

    if os.getenv("KDC_HOST", None):
        conn.update(kdc_admin_host=os.getenv("KDC_HOST"))
        conn.update(kdc_host=os.getenv("KDC_HOST"))

    module_args(
        {
            **conn,
            "state": "present",
            "kdc_type": "Red Hat IPA",
            "krb_enc_types": ["aes256-cts", "aes128-cts", "rc4-hmac"],
            "security_realm": "CLDR.INTERNAL",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        }
    )
   
    with pytest.raises(AnsibleExitJson) as e:
        cm_kerberos.main()

    assert e.value.changed == True

def test_enable_invalid_admin_password(module_args, conn, request):

    if os.getenv("KDC_ADMIN_USER", None):
        conn.update(kdc_admin_user=os.getenv("KDC_ADMIN_USER"))

    if os.getenv("KDC_HOST", None):
        conn.update(kdc_admin_host=os.getenv("KDC_HOST"))
        conn.update(kdc_host=os.getenv("KDC_HOST"))

    module_args(
        {
            **conn,
            "state": "present",
            "kdc_type": "Red Hat IPA",
            "krb_enc_types": ["aes256-cts", "aes128-cts", "rc4-hmac"],
            "security_realm": "CLDR.INTERNAL",
            "kdc_admin_password": "wrongPass",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        }
    )
   
    with pytest.raises(AnsibleFailJson, match="Error during Import KDC Account Manager Credentials command") as e:
        cm_kerberos.main()
        print("At end")

def test_pytest_disable_kerberos(module_args, conn):
    
    module_args(
        {
            **conn,
            "state": "absent"
        }
    )
   
    with pytest.raises(AnsibleExitJson) as e:
        cm_kerberos.main()

    # assert e.value.changed == True
