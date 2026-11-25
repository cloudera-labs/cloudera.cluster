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

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from ansible_collections.cloudera.cluster.plugins.modules import cluster_info
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)


@pytest.fixture
def cluster_api(monkeypatch):
    api = Mock()
    api.read_clusters.return_value = SimpleNamespace(items=["cluster"])
    api.read_cluster.return_value = "cluster"
    monkeypatch.setattr(cluster_info, "ClustersResourceApi", Mock(return_value=api))
    monkeypatch.setattr(
        cluster_info, "parse_cluster_result", lambda cluster: {"name": cluster}
    )
    monkeypatch.setattr(
        cluster_info.ClusterInfo,
        "initialize_client",
        lambda self: setattr(self, "api_client", object()),
    )
    return api


@pytest.fixture
def args():
    return {"host": "example.test", "username": "user", "password": "password"}


@pytest.mark.parametrize("parameter", ["cluster_type", "type"])
@pytest.mark.parametrize("cluster_type", ["any", "base", "compute", "experience"])
def test_cluster_type_filter(module_args, args, cluster_api, parameter, cluster_type):
    args[parameter] = cluster_type
    module_args(args)

    with pytest.raises(AnsibleExitJson) as result:
        cluster_info.main()

    cluster_api.read_clusters.assert_called_once_with(cluster_type=cluster_type)
    cluster_api.read_cluster.assert_not_called()
    assert result.value.clusters == [{"name": "cluster"}]
    assert result.value.changed is False


@pytest.mark.parametrize("parameters", [{}, {"cluster_type": None}, {"type": None}])
def test_cluster_type_omitted(module_args, args, cluster_api, parameters):
    args.update(parameters)
    module_args(args)

    with pytest.raises(AnsibleExitJson) as result:
        cluster_info.main()

    cluster_api.read_clusters.assert_called_once_with()
    assert result.value.clusters == [{"name": "cluster"}]


@pytest.mark.parametrize("name_parameter", ["name", "cluster_name", "cluster"])
def test_name_without_cluster_type(module_args, args, cluster_api, name_parameter):
    args[name_parameter] = "example"
    module_args(args)

    with pytest.raises(AnsibleExitJson) as result:
        cluster_info.main()

    cluster_api.read_cluster.assert_called_once_with(cluster_name="example")
    cluster_api.read_clusters.assert_not_called()
    assert result.value.clusters == [{"name": "cluster"}]


@pytest.mark.parametrize("name_parameter", ["name", "cluster_name", "cluster"])
@pytest.mark.parametrize("type_parameter", ["cluster_type", "type"])
@pytest.mark.parametrize("cluster_type", ["base", None])
def test_name_and_cluster_type_are_mutually_exclusive(
    module_args,
    args,
    cluster_api,
    name_parameter,
    type_parameter,
    cluster_type,
):
    args.update({name_parameter: "example", type_parameter: cluster_type})
    module_args(args)

    with pytest.raises(AnsibleFailJson, match="mutually exclusive"):
        cluster_info.main()

    cluster_api.read_cluster.assert_not_called()
    cluster_api.read_clusters.assert_not_called()


@pytest.mark.parametrize("parameter", ["cluster_type", "type"])
def test_invalid_cluster_type(module_args, args, cluster_api, parameter):
    args[parameter] = "invalid"
    module_args(args)

    with pytest.raises(AnsibleFailJson, match="value of cluster_type must be one of"):
        cluster_info.main()

    cluster_api.read_cluster.assert_not_called()
    cluster_api.read_clusters.assert_not_called()
