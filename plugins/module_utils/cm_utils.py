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

"""
A common Ansible Module functions for Cloudera Manager
"""

import io
import json
import logging

from functools import wraps
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning, MaxRetryError, HTTPError
from urllib3.util import Url
from urllib.parse import urljoin

from ansible.module_utils.basic import AnsibleModule

from cm_client import ApiClient, Configuration
from cm_client.rest import ApiException, RESTClientObject
from cm_client.apis.cloudera_manager_resource_api import ClouderaManagerResourceApi


__credits__ = ["frisch@cloudera.com"]
__maintainer__ = ["wmudge@cloudera.com"]

"""
A common Ansible Module for API access to Cloudera Manager.
"""

class ClouderaManagerModule(object):
    @classmethod
    def handle_process(cls, f):
        """Wrapper to handle log capture and common HTTP errors"""

        @wraps(f)
        def _impl(self, *args, **kwargs):
            try:
                self._initialize_client()
                result = f(self, *args, **kwargs)
                if self.debug:
                    self.log_out = self._get_log()
                    self.log_lines.append(self.log_out.splitlines())
                return result
            except ApiException as ae:
                body = ae.body.decode("utf-8")
                if body != "":
                    body = json.loads(body)
                self.module.fail_json(
                    msg="API error: " + str(ae.reason), status_code=ae.status, body=body
                )
            except MaxRetryError as maxe:
                self.module.fail_json(msg="Request error: " + str(maxe.reason))
            except HTTPError as he:
                self.module.fail_json(msg="HTTP request: " + str(he))

        return _impl

    """A base Cloudera Manager (CM) module class"""

    def __init__(self, module):
        # Set common parameters
        self.module = module
        self.url = self._get_param("url", None)
        self.force_tls = self._get_param("force_tls")
        self.host = self._get_param("host")
        self.port = self._get_param("port")
        self.version = self._get_param("version")
        self.username = self._get_param("username")
        self.password = self._get_param("password")
        self.verify_tls = self._get_param("verify_tls")
        self.debug = self._get_param("debug")
        self.agent_header = self._get_param("agent_header")

        # Initialize common return values
        self.log_out = None
        self.log_lines = []
        self.changed = False

        # Configure the core CM API client parameters
        config = Configuration()
        config.username = self.username
        config.password = self.password
        config.verify_ssl = self.verify_tls
        config.debug = self.debug

        # Configure logging
        _log_format = (
            "%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s"
        )
        if self.debug:
            self._setup_logger(logging.DEBUG, _log_format)
            self.logger.debug("CM API agent: %s", self.agent_header)
        else:
            self._setup_logger(logging.ERROR, _log_format)

        if self.verify_tls is False:
            disable_warnings(InsecureRequestWarning)

    def _get_param(self, param, default=None):
        """Fetches an Ansible input parameter if it exists, else returns optional default or None"""
        if self.module is not None:
            return self.module.params[param] if param in self.module.params else default
        return default

    def _setup_logger(self, log_level, log_format):
        """Configures the logging of the HTTP activity"""
        self.logger = logging.getLogger("urllib3")
        self.logger.setLevel(log_level)

        self.__log_capture = io.StringIO()
        handler = logging.StreamHandler(self.__log_capture)
        handler.setLevel(log_level)

        formatter = logging.Formatter(log_format)
        handler.setFormatter(formatter)

        self.logger.addHandler(handler)

    def _get_log(self):
        """Retrieves the contents of the captured log"""
        contents = self.__log_capture.getvalue()
        self.__log_capture.truncate(0)
        return contents

    def _initialize_client(self):
        """Configures and creates the API client"""
        config = Configuration()

        # If provided a CML endpoint URL, use it directly
        if self.url:
            config.host = self.url
        # Otherwise, run discovery on missing parts
        else:
            config.host = self._discover_endpoint(config)

        # Create and set the API Client
        self.api_client = ApiClient()

    def get_auth_headers(self, config):
        """Constructs a Basic Auth header dictionary from the Configuration.
        This dictionary can be used directly with the API client's REST client."""
        headers = dict()
        auth = config.auth_settings().get("basic")
        headers[auth["key"]] = auth["value"]
        return headers

    def _discover_endpoint(self, config):
        """Discovers the scheme and version of a potential Cloudara Manager host"""
        # Get the authentication headers and REST client
        headers = self.get_auth_headers(config)
        rest = RESTClientObject()

        # Resolve redirects to establish HTTP scheme and port
        pre_rendered = Url(
            scheme="https" if self.force_tls else "http", host=self.host, port=self.port
        )
        rendered = rest.pool_manager.request(
            "GET", pre_rendered.url, headers=headers.copy()
        )
        rendered_url = rendered.geturl()

        # Discover API version if not set
        if not self.version:
            pre_versioned = urljoin(rendered_url, "/api/version")
            versioned = rest.pool_manager.request("GET", pre_versioned, headers=headers)
            self.version = versioned.data.decode("utf-8")

        # Construct the discovered API endpoint
        return urljoin(rendered_url, "/api/" + self.version)

    def set_session_cookie(self):
        """Utility to cache the session cookie for intra-module operations."""
        if not self.api_client.last_response:
            api_instance = ClouderaManagerResourceApi(self.api_client)
            api_instance.get_version()
        self.api_client.cookie = self.api_client.last_response.getheader("Set-Cookie")

    def call_api(self, path, method, query=None, field="items", body=None):
        """Wrapper to call a CM API endpoint path directly."""
        path_params = []
        header_params = {}
        header_params["Accept"] = self.api_client.select_header_accept(
            ["application/json"]
        )
        header_params["Content-Type"] = self.api_client.select_header_content_type(
            ["application/json"]
        )

        results = self.api_client.call_api(
            path,
            method,
            path_params,
            query,
            header_params,
            body,
            auth_settings=["basic"],
            _preload_content=False,
        )

        if 200 >= results[1] <= 299:
            data = json.loads(results[0].data.decode("utf-8"))
            if field in data:
                data = data[field]
            return data if type(data) is list else [data]
        else:
            self.module.fail_json(
                msg="Error interacting with CM resource", status_code=results[1]
            )

    @staticmethod
    def ansible_module_discovery(argument_spec={}, required_together=[], **kwargs):
        """INTERNAL: Creates the Ansible module argument spec and dependencies for CM API endpoint discovery.
        Typically, modules will use the ansible_module method to include direct API endpoint URL support.
        """
        return AnsibleModule(
            argument_spec=dict(
                **argument_spec,
                host=dict(type="str", aliases=["hostname"]),
                port=dict(type="int", default=7180),
                version=dict(type="str"),
                force_tls=dict(type="bool", default=False),
                verify_tls=dict(
                    required=False, type="bool", default=True, aliases=["tls"]
                ),
                username=dict(required=True, type="str"),
                password=dict(required=True, type="str", no_log=True),
                debug=dict(
                    required=False,
                    type="bool",
                    default=False,
                    aliases=["debug_endpoints"],
                ),
                agent_header=dict(
                    required=False, type="str", default="ClouderaFoundry"
                ),
            ),
            required_together=required_together + [["username", "password"]],
            **kwargs,
        )

    @staticmethod
    def ansible_module(
        argument_spec={},
        mutually_exclusive=[],
        required_one_of=[],
        required_together=[],
        **kwargs
    ):
        """Creates the base Ansible module argument spec and dependencies, including discovery and direct endpoint URL support."""
        return ClouderaManagerModule.ansible_module_discovery(
            argument_spec=dict(
                **argument_spec,
                url=dict(type="str", aliases=["endpoint", "cm_endpoint_url"]),
            ),
            mutually_exclusive=mutually_exclusive + [["url", "host"]],
            required_one_of=required_one_of + [["url", "host"]],
            required_together=required_together,
            **kwargs,
        )
