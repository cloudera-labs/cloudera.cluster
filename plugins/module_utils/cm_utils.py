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
from ansible.module_utils.common.dict_transformations import recursive_diff
from ansible.module_utils.common.text.converters import to_native, to_text
from time import sleep
from cm_client import (
    ApiBulkCommandList,
    ApiClient,
    ApiCommand,
    ApiCommandList,
    ApiConfig,
    ApiConfigList,
    ApiEntityTag,
    Configuration,
)
from cm_client.rest import ApiException, RESTClientObject
from cm_client.apis.cloudera_manager_resource_api import ClouderaManagerResourceApi
from cm_client.apis.commands_resource_api import CommandsResourceApi


__credits__ = ["frisch@cloudera.com"]
__maintainer__ = ["wmudge@cloudera.com"]


def wait_bulk_commands(
    api_client: ApiClient,
    commands: ApiBulkCommandList,
    polling: int = 120,
    delay: int = 10,
):
    if commands.errors:
        error_msg = "\n".join(commands.errors)
        raise Exception(error_msg)

    for cmd in commands.items:
        # Serial monitoring
        wait_command(api_client, cmd, polling, delay)


def wait_commands(
    api_client: ApiClient,
    commands: ApiCommandList,
    polling: int = 120,
    delay: int = 10,
):
    for cmd in commands.items:
        # Serial monitoring
        wait_command(api_client, cmd, polling, delay)


def wait_command(
    api_client: ApiClient,
    command: ApiCommand,
    polling: int = 120,
    delay: int = 10,
    retry: int = 0,
):
    poll_count = 0
    retry_count = 0

    while command.active or retry_count < retry:
        if poll_count > polling:
            raise Exception("Command timeout: " + str(command.id))
        sleep(delay)
        poll_count += 1
        retry_count += 1
        command = CommandsResourceApi(api_client).read_command(command.id)
    if not command.success:
        raise Exception(command.result_message)


def normalize_output(entity: dict, filter: list) -> dict:
    output = {}
    for k in filter:
        if k == "tags":
            output[k] = {entry["name"]: entry["value"] for entry in entity[k]}
        else:
            output[k] = entity[k]

    return output


def normalize_values(add: dict) -> dict:
    """Normalize parameter values. Strings have whitespace trimmed, integers are
    converted to strings, and Boolean values are converted their string representation
    and lowercased.

    Args:
        add (dict): Parameters to review

    Returns:
        dict: Normalized parameters
    """

    def _normalize(value):
        if type(value) is str:
            return value.strip()
        elif type(value) is int:
            return str(value)
        elif type(value) is bool:
            return str(value).lower()
        else:
            return value

    return {k: _normalize(v) for k, v in add.items()}


def resolve_parameter_changeset(
    current: dict,
    incoming: dict,
    purge: bool = False,
    skip_redacted: bool = False,
) -> dict:
    """Produce a change set between two parameter dictionaries.

    The function will normalize parameter values to remove whitespace from strings,
    convert integers and Booleans to their string representations.

    Args:
        current (dict): Existing parameters
        incoming (dict): Declared parameters
        purge (bool, optional): Flag to reset any current parameters not found in the declared set. Defaults to False.
        skip_redacted (bool, optional): Flag to not include parameters with REDACTED values in the changeset. Defaults to False.

    Returns:
        dict: A change set of the updates
    """
    updates = {}

    diff = recursive_diff(current, normalize_values(incoming))

    if diff is not None:
        # TODO Lookup default for v=None to avoid issues with CM
        # CM sometimes fails to find the default value for a parameter
        # However, a view=full will return the default, so if we can
        # change this method's signature to include that reference, we
        # can short-circuit CM's problematic lookup of the default value.
        updates = {
            k: v
            for k, v in diff[1].items()
            if (k in current and not skip_redacted)
            or (k in current and (skip_redacted and current[k] != "REDACTED"))
            or (k not in current and v is not None)
        }

        if purge:
            # Add the remaining non-default values for removal
            updates = {
                **updates,
                **{k: None for k in diff[0].keys() if k not in diff[1]},
            }

    return updates


def reconcile_config_list_updates(
    existing: ApiConfigList,
    config: dict,
    purge: bool = False,
    skip_redacted: bool = False,
) -> tuple[ApiConfigList, dict, dict]:
    """Return a reconciled configuration list and the change deltas.

    The function will normalize parameter values to remove whitespace from strings and
    convert integers and Booleans to their string representations. Optionally, the
    function will reset undeclared parameters or skip parameters that it is unable to
    resolve, i.e. REDACTED parameter values.

    Args:
        existing (ApiConfigList): Existing parameters
        config (dict): Declared parameters
        purge (bool, optional): Flag to reset any current parameters not found in the declared set. Defaults to False.
        skip_redacted (bool, optional): Flag to not include parameters with REDACTED values in the changeset. Defaults to False.
    Returns:
        tuple[ApiConfigList, dict, dict]: Updated configuration list and the before and after deltas
    """
    current = {r.name: r.value for r in existing.items}
    changeset = resolve_parameter_changeset(current, config, purge, skip_redacted)

    before = {k: current[k] if k in current else None for k in changeset.keys()}
    after = changeset

    reconciled_config = ApiConfigList(
        items=[ApiConfig(name=k, value=v) for k, v in changeset.items()],
    )

    return (reconciled_config, before, after)


def resolve_tag_updates(
    current: dict,
    incoming: dict,
    purge: bool = False,
) -> tuple[dict, dict]:
    incoming_tags = {
        k: str(v)
        for k, v in incoming.items()
        if (type(v) is str and v.strip() != "")
        or (type(v) is not str and v is not None)
    }

    delta_add = {}
    delta_del = {}

    diff = recursive_diff(incoming_tags, current)

    if diff is not None:
        delta_add = diff[0]

        if purge:
            delta_del = diff[1]
        else:
            delta_del = {k: v for k, v in diff[1].items() if k in diff[0]}

    return (delta_add, delta_del)


class TagUpdates(object):
    def __init__(
        self,
        existing: list[ApiEntityTag],
        updates: dict,
        purge: bool,
    ) -> None:
        (_additions, _deletions) = resolve_tag_updates(
            current={t.name: t.value for t in existing},
            incoming=updates,
            purge=purge,
        )

        self.diff = dict(
            before=_deletions,
            after=_additions,
        )

        self.additions = [ApiEntityTag(k, v) for k, v in _additions.items()]
        self.deletions = [ApiEntityTag(k, v) for k, v in _deletions.items()]

    @property
    def changed(self) -> bool:
        return bool(self.additions) or bool(self.deletions)


class ConfigListUpdates(object):
    def __init__(self, existing: ApiConfigList, updates: dict, purge: bool) -> None:
        current = {r.name: r.value for r in existing.items}
        changeset = resolve_parameter_changeset(current, updates, purge)

        self.diff = dict(
            before={k: current[k] if k in current else None for k in changeset.keys()},
            after=changeset,
        )

        self.config = ApiConfigList(
            items=[ApiConfig(name=k, value=v) for k, v in changeset.items()],
        )

    @property
    def changed(self) -> bool:
        return bool(self.config.items)


class ClusterTemplate(object):
    IDEMPOTENT_IDS = frozenset(
        ["refName", "name", "clusterName", "hostName", "product"],
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
                f"Base and fragment arguments must be the same type: base[{type(base)}], fragment[{type(fragment)}]",
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
                        f"Overriding value for key [{crumb}]], Old: [{base[key]}], New: [{value}]",
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
                                self.IDEMPOTENT_IDS,
                            )
                        ],
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
                            ],
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
                    status_code=ae.status,
                )
                if ae.body:
                    try:
                        err.update(msg=json.loads(ae.body)["message"])
                    except Exception:
                        err.update(msg="API error: " + to_text(ae.reason))
                else:
                    err.update(msg="API error: " + to_text(ae.reason))

                self.module.fail_json(**_add_log(err))
            except MaxRetryError as maxe:
                err = dict(
                    msg="Request error: " + to_text(maxe.reason),
                    url=to_text(maxe.url),
                )
                self.module.fail_json(**_add_log(err))
            except HTTPError as he:
                err = dict(msg="HTTP request: " + str(he))
                self.module.fail_json(**_add_log(err))

        return _impl

    def __init__(self, module: AnsibleModule):
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
        self.proxy_server = self.get_param("proxy")

        # Initialize common return values
        self.changed = False

        # Configure the core CM API client parameters
        config = Configuration()
        config.username = self.username
        config.password = self.password
        config.verify_ssl = self.verify_tls
        config.debug = self.debug

        # Configure HTTP proxy server
        if self.proxy_server:
            config.proxy = self.proxy_server

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

        # If provided a CM endpoint URL, use it directly
        if self.url:
            config.host = str(self.url).rstrip(" /")
        # Otherwise, run discovery on missing parts
        else:
            config.host = self.discover_endpoint(config)

        # Create and set the API Client
        self.api_client = ApiClient()

        # Update the User Agent
        self.api_client.user_agent = self.agent_header

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
            scheme="https" if self.force_tls else "http",
            host=self.host,
            port=self.port,
        )
        rendered = rest.pool_manager.request(
            "GET",
            pre_rendered.url,
            headers=headers.copy(),
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
            if versioned.status != 200:
                self.module.fail_json(
                    "Unable to retrieve API version",
                    status=to_native(versioned.status),
                    reason=to_native(versioned.reason),
                )
            self.version = versioned.data.decode("utf-8")

        # Construct the discovered API endpoint
        return urljoin(rendered_url, "/api/" + self.version)

    def set_session_cookie(self):
        """Utility to cache the session cookie for intra-module operations."""
        if not self.api_client.last_response:
            api_instance = ClouderaManagerResourceApi(self.api_client)
            api_instance.get_version()
        self.api_client.cookie = self.api_client.last_response.getheader("Set-Cookie")

    def wait_for_command_state(self, command_id, polling_interval):
        """
        Waits for a command to complete by polling the its state until it completes.
        A wait for the specified interval is done between each check.

        Inputs:
            command_id : The identifier of the command to monitor.
            polling_interval: The time (in seconds) to wait between polling attempts.

        Return:
            tuple: The full response from `read_command_with_http_info`, containing command details.
        """
        command_api_instance = CommandsResourceApi(self.api_client)
        while True:
            get_command_state = command_api_instance.read_command_with_http_info(
                command_id=command_id,
            )
            state = get_command_state[0].active
            if not state:
                break
            sleep(polling_interval)
        return get_command_state

    def call_api(self, path, method, query=None, field="items", body=None):
        """Wrapper to call a CM API endpoint path directly."""
        path_params = []
        header_params = {}
        header_params["Accept"] = self.api_client.select_header_accept(
            ["application/json"],
        )
        header_params["Content-Type"] = self.api_client.select_header_content_type(
            ["application/json"],
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
        return data if isinstance(data, list) else [data]

    def get_cm_config(self, scope: str = "full") -> list[ApiConfig]:
        return ClouderaManagerResourceApi(self.api_client).get_config(view=scope).items

    def wait_command(self, command: ApiCommand, polling: int = 10, delay: int = 5):
        """
        Waits for a specified command to complete, polling its status at regular intervals.
        If the command exceeds the polling limit, it fails with a timeout error.
        If the command completes unsuccessfully, it fails with the command's result message.

        Args:
            command (ApiCommand): The command object to monitor.
            polling (int, optional): The maximum number of polling attempts before timing out. Default is 10.
            delay (int, optional): The time (in seconds) to wait between polling attempts. Default is 5.

        Raises:
            module.fail_json: If the command times out or fails.

        Returns:
            None: The function returns successfully if the command completes and is marked as successful.
        """
        poll_count = 0
        while command.active:
            if poll_count > polling:
                self.module.fail_json(msg="Command timeout: " + str(command.id))
            sleep(delay)
            poll_count += 1
            command = CommandsResourceApi(self.api_client).read_command(command.id)
        if not command.success:
            self.module.fail_json(
                msg=to_text(command.result_message),
                command_id=to_text(command.id),
            )

    def wait_commands(
        self,
        commands: ApiBulkCommandList,
        polling: int = 10,
        delay: int = 5,
    ):
        """
        Waits for a list of commands to complete, polling each status at regular intervals.
        If a command exceeds the polling limit, it fails with a timeout error.
        If a command completes unsuccessfully, it fails with the command's result message.

        Args:
            commands (ApiBulkCommandList): Cloudera Manager bulk commands

        Raises:
            module.fail_json: If the command times out or fails.

        Returns:
            none: The function returns successfully if the commands complete and are marked as successful.
        """
        if commands.errors:
            error_msg = "\n".join(commands.errors)
            self.module.fail_json(msg=error_msg)

        for c in commands.items:
            # Not in parallel...
            self.wait_command(c, polling, delay)

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
                    required=False,
                    type="bool",
                    default=True,
                    aliases=["tls"],
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
                    required=False,
                    type="str",
                    default="ClouderaFoundry",
                    aliases=["user_agent"],
                ),
                proxy_server=dict(
                    required=False,
                    type="str",
                    aliases=["proxy", "http_proxy"],
                ),
            ),
            required_together=required_together + [["username", "password"]],
            **kwargs,
        )

    @staticmethod
    def ansible_module(
        argument_spec={},
        bypass_checks=False,
        no_log=False,
        mutually_exclusive=[],
        required_together=[],
        required_one_of=[],
        add_file_common_args=False,
        supports_check_mode=False,
        required_if=None,
        required_by=None,
    ):
        """
        Creates the base Ansible module argument spec and dependencies,
        including discovery and direct endpoint URL support.
        """
        return ClouderaManagerModule.ansible_module_internal(
            dict(
                **argument_spec,
                url=dict(type="str", aliases=["endpoint", "cm_endpoint_url"]),
            ),
            required_together,
            bypass_checks=bypass_checks,
            no_log=no_log,
            mutually_exclusive=mutually_exclusive + [["url", "host"]],
            required_one_of=required_one_of + [["url", "host"]],
            add_file_common_args=add_file_common_args,
            supports_check_mode=supports_check_mode,
            required_if=required_if,
            required_by=required_by,
        )


class ClouderaManagerMutableModule(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaManagerMutableModule, self).__init__(module)
        self.message = self.get_param("message")

    @staticmethod
    def ansible_module(
        argument_spec={},
        bypass_checks=False,
        no_log=False,
        mutually_exclusive=[],
        required_together=[],
        required_one_of=[],
        add_file_common_args=False,
        supports_check_mode=False,
        required_if=None,
        required_by=None,
    ):
        return ClouderaManagerModule.ansible_module(
            argument_spec=dict(
                **argument_spec,
                message=dict(default="Managed by Ansible", aliases=["msg"]),
            ),
            bypass_checks=bypass_checks,
            no_log=no_log,
            mutually_exclusive=mutually_exclusive,
            required_together=required_together,
            required_one_of=required_one_of,
            add_file_common_args=add_file_common_args,
            supports_check_mode=supports_check_mode,
            required_if=required_if,
            required_by=required_by,
        )
