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

"""
A common Ansible Module functions for Cloudera Manager
"""

import io
import json
import logging

from functools import wraps
from typing import Union
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning, MaxRetryError, HTTPError
from urllib3.util import Url
from urllib.parse import urljoin
from time import sleep
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_text
from time import sleep
from cm_client import ApiClient, ApiConfigList, Configuration
from cm_client.rest import ApiException, RESTClientObject
from cm_client.apis.cloudera_manager_resource_api import ClouderaManagerResourceApi
from cm_client.apis.commands_resource_api import CommandsResourceApi


__credits__ = ["frisch@cloudera.com"]
__maintainer__ = ["wmudge@cloudera.com"]


class ClusterTemplate(object):
    IDEMPOTENT_IDS = frozenset(
        ["refName", "name", "clusterName", "hostName", "product"]
    )
    UNIQUE_IDS = frozenset(["repositories"])

    def __init__(self, warn_fn, error_fn) -> None:
        self._warn = warn_fn
        self._error = error_fn

    def merge(self, base: Union[dict, list], fragment: Union[dict, list]) -> bool:
        if isinstance(base, dict) and isinstance(fragment, dict):
            self._update_dict(base, fragment)
        elif isinstance(base, list) and isinstance(fragment, list):
            self._update_list(base, fragment)
        else:
            raise TypeError(
                f"Base and fragment arguments must be the same type: base[{type(base)}], fragment[{type(fragment)}]"
            )

    def _update_dict(self, base, fragment, breadcrumbs="") -> None:
        for key, value in fragment.items():
            crumb = breadcrumbs + "/" + key

            # If the key is idempotent, error that the values are different
            if key in self.IDEMPOTENT_IDS:
                if base[key] != value:
                    self._error(f"Unable to override value for distinct key [{crumb}]")
                continue

            # If it's a new key, add to the bae
            if key not in base:
                base[key] = value
            # If the value is a dictionary, merge
            elif isinstance(value, dict):
                self._update_dict(base[key], value, crumb)
            # If the value is a list, merge
            elif isinstance(value, list):
                self._update_list(base[key], value, crumb)
            # Else the value is a scalar
            else:
                # If the value is different, override
                if base[key] != value:
                    self._warn(
                        f"Overriding value for key [{crumb}]], Old: [{base[key]}], New: [{value}]"
                    )
                    base[key] = value

            if key in self.UNIQUE_IDS:
                base[key] = list(set(base[key]))
                base[key].sort(key=lambda x: json.dumps(x, sort_keys=True))

    def _update_list(self, base, fragment, breadcrumbs="") -> None:
        for entry in fragment:
            if isinstance(entry, dict):
                # Discover if the incoming dict has an idempotent key
                idempotent_key = next(
                    iter(
                        [
                            id
                            for id in set(entry.keys()).intersection(
                                self.IDEMPOTENT_IDS
                            )
                        ]
                    ),
                    None,
                )

                # Merge the idemponent key's dictionary rather than appending as a new entry
                if idempotent_key:
                    existing_entry = next(
                        iter(
                            [
                                i
                                for i in base
                                if isinstance(i, dict)
                                and idempotent_key in i
                                and i[idempotent_key] == entry[idempotent_key]
                            ]
                        ),
                        None,
                    )
                    if existing_entry:
                        self._update_dict(
                            existing_entry,
                            entry,
                            f"{breadcrumbs}/[{idempotent_key}={entry[idempotent_key]}]",
                        )
                        continue
                # Else, drop to appending the entry as net new
            base.append(entry)

        base.sort(key=lambda x: json.dumps(x, sort_keys=True))


class ClouderaManagerModule(object):
    """Base Ansible Module for API access to Cloudera Manager."""

    @classmethod
    def handle_process(cls, f):
        """Wrapper to handle API, retry, and HTTP errors."""

        @wraps(f)
        def _impl(self, *args, **kwargs):
            def _add_log(err):
                if self.debug:
                    log = self.log_capture.getvalue()
                    err.update(debug=log, debug_lines=log.split("\n"))
                return err

            try:
                self.initialize_client()
                return f(self, *args, **kwargs)
            except ApiException as ae:
                err = dict(
                    msg="API error: " + to_text(ae.reason),
                    status_code=ae.status,
                )
                if ae.body:
                    try:
                        err.update(body=json.loads(ae.body))
                    except Exception:
                        err.update(body=ae.body.decode("utf-8")),

                self.module.fail_json(**_add_log(err))
            except MaxRetryError as maxe:
                err = dict(
                    msg="Request error: " + to_text(maxe.reason), url=to_text(maxe.url)
                )
                self.module.fail_json(**_add_log(err))
            except HTTPError as he:
                err = dict(msg="HTTP request: " + str(he))
                self.module.fail_json(**_add_log(err))

        return _impl

    def __init__(self, module):
        # Set common parameters
        self.module = module
        self.url = self.get_param("url", None)
        self.force_tls = self.get_param("force_tls")
        self.host = self.get_param("host")
        self.port = self.get_param("port")
        self.version = self.get_param("version")
        self.username = self.get_param("username")
        self.password = self.get_param("password")
        self.verify_tls = self.get_param("verify_tls")
        self.ssl_ca_cert = self.get_param("ssl_ca_cert")
        self.debug = self.get_param("debug")
        self.agent_header = self.get_param("agent_header")

        # Initialize common return values
        self.changed = False

        # Configure the core CM API client parameters
        config = Configuration()
        config.username = self.username
        config.password = self.password
        config.verify_ssl = self.verify_tls
        config.debug = self.debug

        # Configure custom validation certificate
        if self.ssl_ca_cert:
            config.ssl_ca_cert = self.ssl_ca_cert

        # Create a common logging format
        log_format = (
            "%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s"
        )

        # Configure the urllib3 logger
        self.logger = logging.getLogger("cloudera.cluster")

        if self.debug:
            root_logger = logging.getLogger()
            root_logger.setLevel(logging.DEBUG)
            root_logger.propagate = True

            self.log_capture = io.StringIO()
            handler = logging.StreamHandler(self.log_capture)

            formatter = logging.Formatter(log_format)
            handler.setFormatter(formatter)

            root_logger.addHandler(handler)

        self.logger.debug("CM API agent: %s", self.agent_header)

        if self.verify_tls is False:
            disable_warnings(InsecureRequestWarning)

    def get_param(self, param, default=None):
        """
        Fetches an Ansible input parameter if it exists, else returns optional
        default or None.
        """
        if self.module is not None:
            return self.module.params[param] if param in self.module.params else default
        return default

    def initialize_client(self):
        """Creates the CM API client"""
        config = Configuration()

        # If provided a CML endpoint URL, use it directly
        if self.url:
            config.host = str(self.url).rstrip(" /")
        # Otherwise, run discovery on missing parts
        else:
            config.host = self.discover_endpoint(config)

        # Create and set the API Client
        self.api_client = ApiClient()

    def get_auth_headers(self, config):
        """
        Constructs a Basic Auth header dictionary from the Configuration. This
        dictionary can be used directly with the API client's REST client.
        """
        headers = dict()
        auth = config.auth_settings().get("basic")
        headers[auth["key"]] = auth["value"]
        return headers

    def discover_endpoint(self, config):
        """Discovers the scheme and version of a potential Cloudara Manager host."""
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

        # Normalize to handle redirects
        try:
            rendered_url = rendered.url
        except Exception:
            rendered_url = rendered.geturl()

        if rendered_url == "/":
            rendered_url = pre_rendered.url

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

    def wait_for_command_state(self,command_id, polling_interval):
        command_api_instance = CommandsResourceApi(self.api_client)
        while True:
            get_command_state = command_api_instance.read_command_with_http_info(command_id=command_id)
            state = get_command_state[0].active
            if not state:
                break
            sleep(polling_interval)
        return True

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

        data = json.loads(results[0].data.decode("utf-8"))
        if field in data:
            data = data[field]
        return data if type(data) is list else [data]

    def get_cm_config(self, scope: str = "summary") -> ApiConfigList:
        return ClouderaManagerResourceApi(self.api_client).get_config(view=scope).items

    @staticmethod
    def ansible_module_internal(argument_spec={}, required_together=[], **kwargs):
        """
        INTERNAL: Creates the Ansible module argument spec and dependencies for
        CM API endpoint discovery. Typically, modules will use the
        ansible_module method to include direct API endpoint URL support.
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
                ssl_ca_cert=dict(type="path", aliases=["tls_cert", "ssl_cert"]),
                username=dict(required=True, type="str", aliases=["user"]),
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
        **kwargs,
    ):
        """
        Creates the base Ansible module argument spec and dependencies,
        including discovery and direct endpoint URL support.
        """
        return ClouderaManagerModule.ansible_module_internal(
            argument_spec=dict(
                **argument_spec,
                url=dict(type="str", aliases=["endpoint", "cm_endpoint_url"]),
            ),
            mutually_exclusive=mutually_exclusive + [["url", "host"]],
            required_one_of=required_one_of + [["url", "host"]],
            required_together=required_together,
            **kwargs,
        )


class ClouderaManagerMutableModule(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaManagerMutableModule, self).__init__(module)
        self.message = self.get_param("message")
        
    @staticmethod
    def ansible_module(
        argument_spec={},
        mutually_exclusive=[],
        required_one_of=[],
        required_together=[],
        **kwargs,
    ):
        return ClouderaManagerModule.ansible_module(
            dict(
                **argument_spec,
                message=dict(default="Managed by Ansible", aliases=["msg"])
            ),
            mutually_exclusive,
            required_one_of,
            required_together,
            **kwargs
        )
