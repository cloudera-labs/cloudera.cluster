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

"""
A common functions for Cloudera Manager hosts
"""

from cm_client import (
    ApiClient,
    ApiHost,
    ApiHostRef,
    HostsResourceApi,
)
from cm_client.rest import ApiException


def get_host(
    api_client: ApiClient, hostname: str = None, host_id: str = None
) -> ApiHost:
    """Retrieve a Host by either hostname or host ID.

    Args:
        api_client (ApiClient): Cloudera Manager API client.
        hostname (str, optional): The cluster hostname. Defaults to None.
        host_id (str, optional): The cluster host ID. Defaults to None.

    Raises:
        ex: ApiException for all non-404 errors.

    Returns:
        ApiHost: Host object. If not found, returns None.
    """
    if hostname:
        return next(
            (
                h
                for h in HostsResourceApi(api_client).read_hosts().items
                if h.hostname == hostname
            ),
            None,
        )
    else:
        try:
            return HostsResourceApi(api_client).read_host(host_id)
        except ApiException as ex:
            if ex.status != 404:
                raise ex
            else:
                return None


def get_host_ref(
    api_client: ApiClient, hostname: str = None, host_id: str = None
) -> ApiHostRef:
    """Retrieve a Host Reference by either hostname or host ID.

    Args:
        api_client (ApiClient): Cloudera Manager API client.
        hostname (str, optional): The cluster hostname. Defaults to None.
        host_id (str, optional): The cluster host ID. Defaults to None.

    Raises:
        ex: ApiException for all non-404 errors.

    Returns:
        ApiHostRef: Host reference object. If not found, returns None.
    """
    host = get_host(api_client, hostname, host_id)

    if host is not None:
        return ApiHostRef(host.host_id, host.hostname)
    else:
        return None
