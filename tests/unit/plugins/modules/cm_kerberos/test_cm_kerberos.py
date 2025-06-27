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

from cm_client.api_client import ApiClient

__metaclass__ = type

import os
import logging
import pytest
import re

from pathlib import Path

from cm_client.rest import ApiException
from cm_client import (
    ClouderaManagerResourceApi,
    ApiConfigList,
    ApiConfig,
)


from ansible_collections.cloudera.cluster.plugins.modules import cm_kerberos
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
    wait_for_command,
)

LOG = logging.getLogger(__name__)


@pytest.fixture(scope="function")
def krb_disabled(cm_api_client, request) -> None:
    """
    Disable any existing Kerberos setup on the target Cloudera on Premise deployment.

    This fixture does not restore any prior configurations.
    """

    cm_api = ClouderaManagerResourceApi(cm_api_client)

    cm_api.delete_credentials_command()

    reset_params = dict(
        krb_enc_types="aes256-cts",
        security_realm="HADOOP.COM",
        kdc_type="MIT KDC",
        kdc_admin_host="",
        kdc_host="",
        krb_auth_enable=False,
        ad_account_prefix="",
        ad_kdc_domain="ou=hadoop,DC=hadoop,DC=com",
        ad_delete_on_regenerate=False,
        ad_set_encryption_types=False,
        kdc_account_creation_host_override="",
        gen_keytab_script="",
    )

    body = ApiConfigList(
        items=[ApiConfig(name=k, value=v) for k, v in reset_params.items()],
    )

    cm_api.update_config(
        message=f"{Path(request.node.parent.name).stem}::{request.node.name}::cleared",
        body=body,
    )


# TODO Should parameterize with a marker
@pytest.fixture(scope="function")
def krb_freeipa(cm_api_client, request, krb_disabled) -> None:
    """
    Reset any existing Kerberos setup on the target Cloudera on Premise deployment.

    This fixture does not restore any prior configurations.
    """

    cm_api = ClouderaManagerResourceApi(cm_api_client)

    setup_params = dict(
        krb_enc_types="aes256-cts aes128-cts rc4-hmac",
        security_realm="HADOOP.COM",
        kdc_type="Red Hat IPA",
        kdc_admin_host=os.getenv("KDC_HOST"),
        kdc_host=os.getenv("KDC_HOST"),
    )

    body = ApiConfigList(
        items=[ApiConfig(name=k, value=v) for k, v in setup_params.items()],
    )

    cm_api.update_config(
        message=f"{Path(request.node.parent.name).stem}::{request.node.name}::enabled",
        body=body,
    )

    cmd = cm_api.import_admin_credentials(
        username=os.getenv("KDC_ADMIN_USER"),
        password=os.getenv("KDC_ADMIN_PASSWORD"),
    )

    try:
        wait_for_command(
            api_client=cm_api_client,
            command=cmd,
        )
    except Exception as e:
        if re.search("user with name", str(e)):
            LOG.info("Reusing existing KDC user for Cloudera Manager")
        else:
            raise e


def test_pytest_enable_kerberos(module_args, conn, krb_disabled, request):

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
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_kerberos.main()

    assert e.value.changed == True

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_kerberos.main()

    assert e.value.changed == False


def test_enable_invalid_admin_password(module_args, conn, krb_disabled, request):

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
        },
    )

    with pytest.raises(
        AnsibleFailJson,
        match="Error during Import KDC Account Manager Credentials command",
    ):
        cm_kerberos.main()


def test_pytest_disable_kerberos(module_args, conn, krb_freeipa):

    module_args({**conn, "state": "absent"})

    with pytest.raises(AnsibleExitJson) as e:
        cm_kerberos.main()

    assert e.value.changed == True

    # Idempotency
    with pytest.raises(AnsibleExitJson) as e:
        cm_kerberos.main()

    assert e.value.changed == False


def test_force_enable_kerberos(module_args, conn, krb_freeipa, request):

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
            "force": True,
            "kdc_type": "Red Hat IPA",
            "krb_enc_types": ["aes256-cts", "aes128-cts", "rc4-hmac"],
            "security_realm": "CLDR.INTERNAL",
            "message": f"{Path(request.node.parent.name).stem}::{request.node.name}",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        cm_kerberos.main()

    assert e.value.changed == True
