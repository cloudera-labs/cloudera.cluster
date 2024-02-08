# Copyright 2024 Cloudera, Inc.
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

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
import json
import os
import pytest

from ansible_collections.cloudera.cluster.plugins.modules import (
    assemble_cluster_template,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClusterTemplate,
)
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)
TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def expected_list(expected: list) -> list:
    expected.sort(key=lambda x: json.dumps(x, sort_keys=True))
    return expected


def test_missing_required(module_args):
    module_args()

    with pytest.raises(AnsibleFailJson, match="dest, src"):
        assemble_cluster_template.main()


def test_missing_dest(module_args):
    module_args({"src": "foo.json"})

    with pytest.raises(AnsibleFailJson, match="dest"):
        assemble_cluster_template.main()


def test_missing_src(module_args):
    module_args({"dest": "foo.json"})

    with pytest.raises(AnsibleFailJson, match="src"):
        assemble_cluster_template.main()


def test_src_not_directory(module_args, tmp_path):
    root_dir = tmp_path / "not_directory"
    root_dir.mkdir()

    invalid_src = root_dir / "invalid_src.json"
    invalid_src.touch()

    module_args(
        {
            "dest": "foo.json",
            "src": str(invalid_src),
        }
    )

    with pytest.raises(AnsibleFailJson, match="not a directory"):
        assemble_cluster_template.main()


def test_src_invalid_file(module_args, tmp_path):
    root_dir = tmp_path / "not_valid"
    root_dir.mkdir()

    invalid_file = root_dir / "invalid_file.txt"
    invalid_file.touch()

    module_args(
        {
            "dest": "foo.json",
            "src": str(root_dir),
        }
    )

    with pytest.raises(AnsibleFailJson, match="JSON parsing error"):
        assemble_cluster_template.main()


def test_src_filtered(module_args, tmp_path):
    root_dir = tmp_path / "filtered"
    root_dir.mkdir()

    content = dict()
    content["test"] = "Test"

    base = root_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    overlay = dict()
    overlay["error"] = True

    filtered = root_dir / "filtered.json"
    filtered.write_text(
        json.dumps(content, indent=2, sort_keys=False), encoding="utf-8"
    )

    results = root_dir / "results.json"

    module_args({"dest": str(results), "src": str(root_dir), "regexp": "^filtered"})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()

    output = json.load(results.open())

    assert "error" not in output
    assert len(output) == 1
    assert "test" in output
    assert output["test"] == "Test"


@pytest.mark.parametrize("key", ClusterTemplate.IDEMPOTENT_IDS)
def test_merge_idempotent_key(module_args, tmp_path, key):
    root_dir = tmp_path / "idempotent"
    root_dir.mkdir()

    content = dict()
    content[key] = "Test"

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    module_args({"dest": str(root_dir / "results.json"), "src": str(fragment_dir)})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()


@pytest.mark.parametrize("key", ClusterTemplate.IDEMPOTENT_IDS)
def test_merge_idempotent_key_conflict(module_args, tmp_path, key):
    root_dir = tmp_path / "idempotent_conflict"
    root_dir.mkdir()

    content = dict()
    content[key] = "Test"

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    content[key] = "Error"
    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    module_args({"dest": str(root_dir / "results.json"), "src": str(fragment_dir)})

    with pytest.raises(AnsibleFailJson, match=f"/{key}"):
        assemble_cluster_template.main()


@pytest.mark.parametrize("key", ClusterTemplate.UNIQUE_IDS)
def test_merge_unique_key(module_args, tmp_path, key):
    root_dir = tmp_path / "unique"
    root_dir.mkdir()

    content = dict()
    content[key] = ["one", "two"]

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    results = root_dir / "results.json"

    module_args({"dest": str(results), "src": str(fragment_dir)})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()

    output = json.load(results.open())

    assert len(output[key]) == 2
    assert output[key] == expected_list(["one", "two"])


@pytest.mark.parametrize("key", ClusterTemplate.UNIQUE_IDS)
def test_merge_unique_key_additional(module_args, tmp_path, key):
    root_dir = tmp_path / "unique_additional"
    root_dir.mkdir()

    content = dict()
    content[key] = ["one", "two"]

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    content[key] = ["one", "three"]
    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    results = root_dir / "results.json"

    module_args({"dest": str(results), "src": str(fragment_dir)})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()

    output = json.load(results.open())

    assert len(output[key]) == 3
    assert output[key] == expected_list(["one", "two", "three"])


def test_merge_list(module_args, tmp_path):
    root_dir = tmp_path / "list"
    root_dir.mkdir()

    content = dict()
    content["test"] = ["one", "two"]

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    content["test"] = ["one", "three"]
    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    results = root_dir / "results.json"

    module_args({"dest": str(results), "src": str(fragment_dir)})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()

    output = json.loads(results.read_text())

    assert len(output["test"]) == 4
    assert output["test"] == expected_list(["one", "two", "one", "three"])


def test_merge_list_nested(module_args, tmp_path):
    root_dir = tmp_path / "list_nested"
    root_dir.mkdir()

    content = dict()
    content["test"] = [["one"], "two"]

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    content["test"] = [["one"], "three"]
    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    results = root_dir / "results.json"

    module_args({"dest": str(results), "src": str(fragment_dir)})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()

    output = json.load(results.open())

    assert len(output["test"]) == 4
    assert output["test"] == expected_list([["one"], ["one"], "two", "three"])


def test_merge_list_idempotent(module_args, tmp_path):
    root_dir = tmp_path / "list_idempotent"
    root_dir.mkdir()

    content = dict()
    content["test"] = [{"name": "Test"}, "two"]

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    content["test"] = [{"name": "Test"}, "three"]
    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    results = root_dir / "results.json"

    module_args({"dest": str(results), "src": str(fragment_dir)})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()

    output = json.load(results.open())

    assert len(output["test"]) == 3
    assert output["test"] == expected_list([{"name": "Test"}, "two", "three"])


def test_merge_list_idempotent_multiple_elements(module_args, tmp_path):
    root_dir = tmp_path / "list_idempotent_multiple_elements"
    root_dir.mkdir()

    content = dict()
    content["test"] = [{"name": "Test"}, {"product": "Product"}, "two"]

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    content["test"] = [{"name": "Test"}, {"product": "Product"}, "three"]
    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    results = root_dir / "results.json"

    module_args({"dest": str(results), "src": str(fragment_dir)})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()

    output = json.load(results.open())

    assert len(output["test"]) == 4
    assert output["test"] == expected_list(
        [{"name": "Test"}, {"product": "Product"}, "two", "three"]
    )


def test_merge_list_idempotent_multiple_keys(module_args, tmp_path):
    root_dir = tmp_path / "list_idempotent_multiple_keys"
    root_dir.mkdir()

    content = dict()
    content["test"] = [{"name": "Test", "product": "Product"}, "two"]

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    content["test"] = [{"name": "Test", "product": "Product"}, "three"]
    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    results = root_dir / "results.json"

    module_args({"dest": str(results), "src": str(fragment_dir)})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()

    output = json.load(results.open())

    assert len(output["test"]) == 3
    assert output["test"] == expected_list(
        [{"name": "Test", "product": "Product"}, "two", "three"]
    )


def test_merge_list_idempotent_append(module_args, tmp_path):
    root_dir = tmp_path / "list_idempotent_append"
    root_dir.mkdir()

    content = dict()
    content["test"] = [{"name": "Test"}, "two"]

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    content["test"] = [{"name": "Additional"}, "three"]
    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    results = root_dir / "results.json"

    module_args({"dest": str(results), "src": str(fragment_dir)})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()

    output = json.load(results.open())

    assert len(output["test"]) == 4
    assert output["test"] == expected_list(
        [{"name": "Test"}, "two", {"name": "Additional"}, "three"]
    )


def test_merge_dict(module_args, tmp_path):
    root_dir = tmp_path / "dict"
    root_dir.mkdir()

    content = dict()
    content["test"] = {"one": 1}

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    content["test"] = {"two": 2}
    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    results = root_dir / "results.json"

    module_args({"dest": str(results), "src": str(fragment_dir)})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()

    output = json.load(results.open())

    assert len(output["test"]) == 2
    assert output["test"] == {"one": 1, "two": 2}


def test_merge_dict_overwrite(module_args, tmp_path):
    root_dir = tmp_path / "dict_overwrite"
    root_dir.mkdir()

    content = dict()
    content["test"] = {"one": 1}

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    content["test"] = {"one": 2}
    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    results = root_dir / "results.json"

    module_args({"dest": str(results), "src": str(fragment_dir)})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()

    output = json.load(results.open())

    assert len(output["test"]) == 1
    assert output["test"] == {"one": 2}


def test_merge_dict_idempotent_key(module_args, tmp_path):
    root_dir = tmp_path / "dict_idempotent_key"
    root_dir.mkdir()

    content = dict()
    content["test"] = {"one": 1}

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    content["test"] = {"one": 2}
    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    results = root_dir / "results.json"

    module_args({"dest": str(results), "src": str(fragment_dir)})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()

    output = json.load(results.open())

    assert len(output["test"]) == 1
    assert output["test"] == {"one": 2}


def test_merge_dict_nested(module_args, tmp_path):
    root_dir = tmp_path / "dict_nested"
    root_dir.mkdir()

    content = dict()
    content["test"] = {"one": {"two": 1}}

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    content["test"] = {"one": {"three": 3}}
    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    results = root_dir / "results.json"

    module_args({"dest": str(results), "src": str(fragment_dir)})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()

    output = json.load(results.open())

    assert len(output["test"]) == 1
    assert len(output["test"]["one"]) == 2
    assert output["test"] == {"one": {"two": 1, "three": 3}}


def test_merge_dict_nested_overwrite(module_args, tmp_path):
    root_dir = tmp_path / "dict_nested_overwrite"
    root_dir.mkdir()

    content = dict()
    content["test"] = {"one": {"two": 1}}

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    content["test"] = {"one": {"two": 2, "three": 3}}
    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    results = root_dir / "results.json"

    module_args({"dest": str(results), "src": str(fragment_dir)})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()

    output = json.load(results.open())

    assert len(output["test"]) == 1
    assert len(output["test"]["one"]) == 2
    assert output["test"] == {"one": {"two": 2, "three": 3}}


def test_merge_dict_nested_idempotent(module_args, tmp_path):
    root_dir = tmp_path / "dict_nested_idempotent"
    root_dir.mkdir()

    content = dict()
    content["test"] = {"one": {"name": "Test"}}

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    content["test"] = {"one": {"name": "Test"}}
    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    results = root_dir / "results.json"

    module_args({"dest": str(results), "src": str(fragment_dir)})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()

    output = json.load(results.open())

    assert len(output["test"]) == 1
    assert len(output["test"]["one"]) == 1
    assert output["test"] == {"one": {"name": "Test"}}


def test_merge_dict_nested_idempotent_conflict(module_args, tmp_path):
    root_dir = tmp_path / "dict_nested_idempotent_conflict"
    root_dir.mkdir()

    content = dict()
    content["test"] = {"one": {"name": "Test"}}

    fragment_dir = root_dir / "fragments"
    fragment_dir.mkdir()

    base = fragment_dir / "base.json"
    base.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    content["test"] = {"one": {"name": "Conflict"}}
    overlay = fragment_dir / "overlay.json"
    overlay.write_text(json.dumps(content, indent=2, sort_keys=False), encoding="utf-8")

    results = root_dir / "results.json"

    module_args({"dest": str(results), "src": str(fragment_dir)})

    with pytest.raises(AnsibleFailJson, match="\/test\/one\/name"):
        assemble_cluster_template.main()


def test_multiple_services(module_args, tmp_path):
    results = tmp_path / "results.json"

    module_args({"dest": str(results), "src": os.path.join(TEST_DIR, "fragments")})

    with pytest.raises(AnsibleExitJson):
        assemble_cluster_template.main()

    output = json.load(results.open())

    assert output["displayName"] == "ExampleClusterTemplate"
    assert output["cdhVersion"] == "1.2.3"
    assert output["cmVersion"] == "4.5.6"

    assert set(output["repositories"]) == set(
        [
            "https://archive.cloudera.com/",
            "https://archive.cloudera.com/schemaregistry",
            "https://archive.cloudera.com/atlas",
        ]
    )

    assert len(output["products"]) == 2
    assert output["products"] == expected_list(
        [
            dict(product="CDH", version="1.2.3"),
            dict(product="FOO", version="9.8.7"),
        ]
    )

    assert output["instantiator"]["clusterName"] == "ExampleCluster"
    assert len(output["instantiator"]["hosts"]) == 1
    assert output["instantiator"]["hosts"] == expected_list(
        [{"hostName": "host.example.com", "hostTemplateRefName": "ExampleHostTemplate"}]
    )

    assert len(output["hostTemplates"]) == 2
    assert output["hostTemplates"] == expected_list(
        [
            {
                "cardinality": 1,
                "refName": "ExampleHostTemplate",
                "roleConfigGroupsRefNames": [
                    "livy-GATEWAY-BASE",
                    "livy-LIVY_SERVER-BASE",
                    "schemaregistry-SCHEMA_REGISTRY_SERVER-BASE",
                ],
            },
            {
                "refName": "AnotherExampleHostTemplate",
                "roleConfigGroupsRefNames": [
                    "atlas-ATLAS_SERVER-BASE",
                    "atlas-GATEWAY-BASE",
                ],
            },
        ]
    )

    assert len(output["services"]) == 3
    assert output["services"] == expected_list(
        [
            {
                "refName": "atlas",
                "serviceType": "ATLAS",
                "displayName": "Atlas",
                "serviceConfigs": [],
                "roleConfigGroups": [
                    {
                        "refName": "atlas-ATLAS_SERVER-BASE",
                        "roleType": "ATLAS_SERVER",
                        "base": True,
                        "configs": [
                            {"name": "atlas_server_http_port", "value": "31000"},
                            {"name": "atlas_server_https_port", "value": "31443"},
                        ],
                    },
                    {
                        "refName": "atlas-GATEWAY-BASE",
                        "roleType": "GATEWAY",
                        "base": True,
                        "configs": [],
                    },
                ],
            },
            {
                "refName": "schemaregistry",
                "serviceType": "SCHEMAREGISTRY",
                "displayName": "Schema Registry",
                "serviceConfigs": [
                    {"name": "database_host", "value": "host.example.com"}
                ],
                "roleConfigGroups": [
                    {
                        "refName": "schemaregistry-SCHEMA_REGISTRY_SERVER-BASE",
                        "roleType": "SCHEMA_REGISTRY_SERVER",
                        "base": True,
                        "configs": [
                            {"name": "schema.registry.port", "value": "7788"},
                            {
                                "name": "schema.registry.ssl.port",
                                "value": "7790",
                            },
                        ],
                    }
                ],
            },
            {
                "refName": "livy",
                "serviceType": "LIVY",
                "displayName": "Livy",
                "roleConfigGroups": [
                    {
                        "refName": "livy-GATEWAY-BASE",
                        "roleType": "GATEWAY",
                        "base": True,
                        "configs": [],
                    },
                    {
                        "refName": "livy-LIVY_SERVER-BASE",
                        "roleType": "LIVY_SERVER",
                        "base": True,
                        "configs": [],
                    },
                ],
            },
        ],
    )
