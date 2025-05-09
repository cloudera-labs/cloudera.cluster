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

import logging
import pytest

from collections.abc import Callable, Generator
from pathlib import Path

from cm_client import (
    ApiConfig,
    ApiConfigList,
    ApiEntityTag,
    ApiHost,
    ApiHostList,
    ApiHostRef,
    ApiHostRefList,
    ApiHostTemplate,
    ApiHostTemplateList,
    ApiHostRef,
    ApiRole,
    ApiRoleConfigGroup,
    ApiRoleConfigGroupRef,
    ApiRoleList,
    ApiService,
    ClouderaManagerResourceApi,
    ClustersResourceApi,
    HostsResourceApi,
    HostTemplatesResourceApi,
    RolesResourceApi,
    ServicesResourceApi,
)
from cm_client.rest import ApiException

from ansible_collections.cloudera.cluster.plugins.modules import host
from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    wait_commands,
    TagUpdates,
    ConfigListUpdates,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.cluster_utils import (
    get_cluster_hosts,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    create_role,
    provision_service_role,
    read_roles,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.host_template_utils import (
    create_host_template_model,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.host_utils import (
    get_host_roles,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_config_group_utils import (
    get_base_role_config_group,
)
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
    deregister_service,
    register_service,
)

LOG = logging.getLogger(__name__)


class TestHostAttached:
    def test_host_create_invalid_cluster(self, conn, module_args):
        module_args(
            {
                **conn,
            }
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()


class TestHostDetached:
    def test_host_create_invalid_cluster(self, conn, module_args):
        module_args(
            {
                **conn,
            }
        )

        with pytest.raises(AnsibleFailJson, match="boom") as e:
            host.main()
