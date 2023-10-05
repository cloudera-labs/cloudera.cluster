#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2023 Cloudera, Inc.
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

"""
A common Ansible plugin functions for Cloudera Manager
"""

import json
import logging

from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning, MaxRetryError, HTTPError
from urllib3.util import Url
from urllib.parse import urljoin

from ansible.errors import AnsibleError
from ansible.module_utils.common.text.converters import to_text
from ansible.plugins.lookup import LookupBase

from cm_client import ApiClient, Configuration
from cm_client.rest import ApiException, RESTClientObject


__maintainer__ = ["wmudge@cloudera.com"]


"""
A common Ansible Lookup plugin for API access to Cloudera Manager.
"""

class ClouderaManagerLookupBase(LookupBase):
    def initialize_client(self):
        # Set up core CM API client parameters
        config = Configuration()
        config.username = self.get_option("username")
        config.password = self.get_option("password")
        config.verify_ssl = self.get_option("verify_tls")
        config.debug = self.get_option("debug")

        # Configure logging
        _log_format = (
            "%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s"
        )
        if self.get_option("debug"):
            self._setup_logger(logging.DEBUG, _log_format)
            self.logger.debug("CM API agent: %s", self.get_option("agent_header"))
        else:
            self._setup_logger(logging.ERROR, _log_format)

        if self.get_option("verify_tls") is False:
            disable_warnings(InsecureRequestWarning)

        # If provided a CM API endpoint URL, use it directly
        if self.get_option("endpoint"):
            config.host = self.get_option("endpoint")
        # Otherwise, run discovery on missing parts
        else:
            config.host = self._discover_endpoint(config)

        self.api_client = ApiClient()

    def _setup_logger(self, log_level, log_format):
        """Configures the logging of the HTTP activity"""
        self.logger = logging.getLogger("urllib3")
        self.logger.setLevel(log_level)

    def _get_auth_headers(self, config):
        """Constructs a Basic Auth header dictionary from the Configuration.
        This dictionary can be used directly with the API client's REST client."""
        headers = dict()
        auth = config.auth_settings().get("basic")
        headers[auth["key"]] = auth["value"]
        return headers

    def _discover_endpoint(self, config):
        """Discovers the scheme and version of a potential Cloudara Manager host"""
        # Get the authentication headers and REST client
        headers = self._get_auth_headers(config)
        rest = RESTClientObject()

        # Resolve redirects to establish HTTP scheme and port
        pre_rendered = Url(
            scheme="https" if self.get_option("force_tls") else "http",
            host=self.get_option("host"),
            port=self.get_option("port"),
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

    def get(self, path, query=None, field="items", body=None):
        """Wrapper to GET a CM API endpoint path directly."""
        path_params = []
        header_params = {}
        header_params["Accept"] = self.api_client.select_header_accept(
            ["application/json"]
        )
        header_params["Content-Type"] = self.api_client.select_header_content_type(
            ["application/json"]
        )

        try:
            results = self.api_client.call_api(
                path,
                "GET",
                path_params,
                query,
                header_params,
                auth_settings=["basic"],
                _preload_content=False,
            )

            if 200 >= results[1] <= 299:
                data = json.loads(results[0].data.decode("utf-8"))
                if field in data:
                    data = data[field]
                return data if type(data) is list else [data]
            else:
                raise AnsibleError(
                    "Error interacting with CM resource. Status code: %s"
                    % to_text(results[1])
                )
        except ApiException as ae:
            body = ae.body.decode("utf-8")
            if body != "":
                body = json.loads(body)
            raise AnsibleError(
                "API error: %s; Status code: %s" % (ae.reason, ae.status),
                obj=body,
                orig_exc=ae,
            )
        except MaxRetryError as maxe:
            raise AnsibleError("Request error: %s" % to_text(maxe.reason))
        except HTTPError as he:
            raise AnsibleError("HTTP request error", orig_exc=he)
