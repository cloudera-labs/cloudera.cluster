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

from ansible_collections.cloudera.cluster.plugins.modules import external_auth
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


@pytest.fixture
def conn():
    conn = dict(username=os.getenv("CM_USERNAME"), password=os.getenv("CM_PASSWORD"))

    if os.getenv("CM_HOST", None):
        conn.update(host=os.getenv("CM_HOST"))

    if os.getenv("CM_PORT", None):
        conn.update(port=os.getenv("CM_PORT"))

    if os.getenv("CM_PROXY", None):
        conn.update(proxy=os.getenv("CM_PROXY"))

    return {
        **conn,
        "verify_tls": "no",
        "debug": "no",
    }


def test_configure_freeipa_configs(module_args, conn):
    conn.update(
        type="freeipa",
        params={
            "ldap_type": "LDAP",
            "auth_backend_order": "LDAP_THEN_DB",
            "ldap_bind_dn": "uid=admin,cn=users,cn=accounts,dc=cldr,dc=internal",
            "ldap_bind_pw": "Supersecret1",
            "ldap_url": "ldaps://freeipa.1.1.1.1.com",
            "ldap_user_search_base": "cn=users,cn=accounts,dc=cldr,dc=internal",
            "ldap_group_search_base": "cn=groups,cn=accounts,dc=cldr,dc=internal",
            "ldap_group_search_filter": "(member={0})",
            "ldap_user_search_filter": "(uid={0})",
        },
        state="present",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        external_auth.main()

    LOG.info(str(e.value.external_auth))


def test_configure_kerberos_configs(module_args, conn):
    conn.update(
        type="kerberos",
        params={
            "kdc_type": "Red Hat IPA",
            "krb_enc_types": "aes256-cts rc4-hmac",
            "public_cloud_status": "on_public_cloud",
            "security_realm": "cldr.internal",
            "kdc_admin_host": "freeipa.1.1.1.1.com",
            "kdc_host": "freeipa.1.1.1.1.com",
        },
        state="present",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        external_auth.main()

    LOG.info(str(e.value.external_auth))


def test_set_custom_freeipa_configs(module_args, conn):
    conn.update(
        type="freeipa",
        params={"LDAP_URL": "ldaps://freeipa.10.0.0.1.com"},
        state="present",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        external_auth.main()

    LOG.info(str(e.value.external_auth))
