# Copyright 2024 Cloudera, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.



FREEIPA_EXTERNAL_CONFIGS = [
        "LDAP_URL",
        "AUTH_BACKEND_ORDER",
        "LDAP_TYPE",
        "LDAP_BIND_PW",
        "LDAP_BIND_DN",
        "LDAP_USER_SEARCH_FILTER",
        "LDAP_USER_SEARCH_BASE",
        "LDAP_GROUP_SEARCH_FILTER",
        "LDAP_GROUP_SEARCH_BASE",
    ]

KERBEROS_EXTERNAL_CONFIGS = [
        "KDC_HOST",
        "KDC_ADMIN_HOST",
        "KRB_ENC_TYPES",
        "KDC_TYPE",
        "SECURITY_REALM",
        "PUBLIC_CLOUD_STATUS",
]