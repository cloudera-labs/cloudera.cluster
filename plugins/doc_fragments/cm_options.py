#!/usr/bin/env python
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


class ModuleDocFragment(object):
    DOCUMENTATION = r"""
    options:
        host:
            description:
                - Hostname of the CM API endpoint.
                - If set, the C(host) parameter will trigger CM API endpoint discovery, which will follow redirects.
                - Mutually exclusive with I(url).
            type: str
            required: False
            aliases:
                - hostname
        port:
            description:
                - Port of the CM API endpoint.
                - If set, CM API endpoint discovery will connect to the designated port first and will follow redirects.
            type: int
            required: False
            default: 7180
        version:
            description:
                - API version of the CM API endpoint.
            type: str
            required: False
            default: True
            aliases:
                - tls
        force_tls:
            description:
                - Flag to force TLS during CM API endpoint discovery.
                - If C(False), discovery will first try HTTP and follow any redirects.
            type: bool
            required: False
            default: False
        verify_tls:
            description:
                - Verify the TLS certificates for the CM API endpoint.
            type: bool
            required: False
            default: True
        ssl_ca_cert:
            description:
                - Path to SSL CA certificate to use for validation.
            type: path
            required: False
            aliases:
                - tls_cert
                - ssl_cert
        username:
            description:
                - Username for access to the CM API endpoint.
            type: str
            required: True
        password:
            description:
                - Password for access to the CM API endpoint.
                - This parameter is set to C(no_log).
            type: str
            required: True
        debug:
            description:
                - Capture the HTTP interaction logs with the CM API endpoint.
            type: bool
            required: False
            default: False
            aliases:
                - debug_endpoints
        agent_header:
            description:
                - Set the HTTP user agent header when interacting with the CM API endpoint.
            type: str
            required: False
            default: ClouderaFoundry
    """
