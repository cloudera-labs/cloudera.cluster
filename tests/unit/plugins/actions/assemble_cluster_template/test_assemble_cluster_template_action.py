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
import re

from dataclasses import dataclass

from unittest.mock import MagicMock

from ansible.errors import AnsibleError, AnsibleActionFail
from ansible.parsing.dataloader import DataLoader
from ansible.playbook.task import Task
from ansible.template import Templar

from ansible_collections.cloudera.cluster.plugins.action.assemble_cluster_template import (
    ActionModule as AssembleClusterTemplateAction,
)

LOG = logging.getLogger(__name__)
TEST_DIR = os.path.dirname(os.path.abspath(__file__))


@dataclass(init=True)
class MockContext:
    task: MagicMock(Task) = MagicMock(Task)
    connection: MagicMock = MagicMock()
    play_context: MagicMock = MagicMock()
    loader: MagicMock(DataLoader) = MagicMock()
    templar: Templar = Templar(loader=MagicMock(DataLoader))
    shared_loader_obj: MagicMock(DataLoader) = None


@pytest.fixture()
def mock_module_exec():
    def setup(plugin):
        plugin._get_module_args = MagicMock()
        plugin._execute_module = MagicMock()

    return setup


def test_empty_parameters(mock_module_exec):
    context = MockContext()
    context.task.async_val = False
    context.play_context.check_mode = False

    plugin = AssembleClusterTemplateAction(**vars(context))

    mock_module_exec(plugin)

    context.task.args = dict()

    results = plugin.run()

    assert results["failed"] == True
    assert results["msg"] == "Both 'src' and 'dest' are required"


def test_missing_src(mock_module_exec, tmp_path):
    context = MockContext()
    context.task.async_val = False
    context.play_context.check_mode = False

    plugin = AssembleClusterTemplateAction(**vars(context))

    mock_module_exec(plugin)

    src_file = tmp_path / "src.json"
    src_file.touch()

    context.task.args = dict(src=str(src_file))

    results = plugin.run()

    assert results["failed"] == True
    assert results["msg"] == "Both 'src' and 'dest' are required"


def test_missing_dest(mock_module_exec, tmp_path):
    context = MockContext()
    context.task.async_val = False
    context.play_context.check_mode = False

    plugin = AssembleClusterTemplateAction(**vars(context))

    mock_module_exec(plugin)

    dest_file = tmp_path / "dest.json"
    dest_file.touch()

    context.task.args = dict(dest=str(dest_file))

    results = plugin.run()

    assert results["failed"] == True
    assert results["msg"] == "Both 'src' and 'dest' are required"


def test_remote_src(mock_module_exec, tmp_path):
    context = MockContext()
    context.task.async_val = False
    context.play_context.check_mode = False

    plugin = AssembleClusterTemplateAction(**vars(context))

    mock_module_exec(plugin)

    src_file = tmp_path / "src.json"
    src_file.touch()

    dest_file = tmp_path / "dest.json"
    dest_file.touch()

    context.task.args = dict(remote_src=True, src=str(src_file), dest=str(dest_file))
    plugin._execute_module.return_value = dict(msg="Module called")

    results = plugin.run()

    assert results["msg"] == "Module called"


def test_src_not_found(mock_module_exec, tmp_path, monkeypatch):
    context = MockContext()
    context.task.async_val = False
    context.play_context.check_mode = False

    plugin = AssembleClusterTemplateAction(**vars(context))

    mock_module_exec(plugin)

    src_file = tmp_path / "src.json"
    src_file.touch()

    dest_file = tmp_path / "dest.json"
    dest_file.touch()

    context.task.args = dict(src=str(src_file), dest=str(dest_file))

    not_found = MagicMock()
    not_found.side_effect = AnsibleError("NOT FOUND")

    monkeypatch.setattr(plugin, "_find_needle", not_found)

    results = plugin.run()

    assert results["failed"] == True
    assert results["msg"] == "NOT FOUND"


def test_src_not_directory(mock_module_exec, tmp_path, monkeypatch):
    context = MockContext()
    context.task.async_val = False
    context.play_context.check_mode = False

    plugin = AssembleClusterTemplateAction(**vars(context))

    mock_module_exec(plugin)

    src_file = tmp_path / "src.json"
    src_file.touch()

    dest_file = tmp_path / "dest.json"
    dest_file.touch()

    context.task.args = dict(src=str(src_file), dest=str(dest_file))
    monkeypatch.setattr(plugin, "_find_needle", MagicMock(return_value=src_file))

    results = plugin.run()

    assert results["failed"] == True
    assert results["msg"] == f"Source, {str(src_file)}, is not a directory"


def test_invalid_regexp(mock_module_exec, tmp_path, monkeypatch):
    context = MockContext()
    context.task.async_val = False
    context.play_context.check_mode = False

    plugin = AssembleClusterTemplateAction(**vars(context))

    mock_module_exec(plugin)

    src_dir = tmp_path / "fragments"
    src_dir.mkdir()

    dest_file = tmp_path / "dest.json"
    dest_file.touch()

    regexp = "["
    context.task.args = dict(src=str(src_dir), dest=str(dest_file), regexp=regexp)
    monkeypatch.setattr(plugin, "_find_needle", MagicMock(return_value=src_dir))

    results = plugin.run()

    assert results["failed"] == True
    assert (
        results["msg"]
        == f"Regular expression, {regexp}, is invalid: unterminated character set at position 0"
    )


def test_assemble_fragments(tmp_path):
    context = MockContext()
    context.task.async_val = False
    context.play_context.check_mode = False

    plugin = AssembleClusterTemplateAction(**vars(context))

    src_dir = tmp_path / "fragments"
    src_dir.mkdir()

    base = src_dir / "base.json"
    base.write_text(json.dumps(dict(one="BASE", two="BASE")))

    overlay = src_dir / "overlay.json"
    overlay.write_text(json.dumps(dict(one="OVERLAY")))

    dest_file = tmp_path / "dest.json"

    def find_in_tmp(fragment, decrypt):
        return os.path.join(src_dir, fragment)

    context.loader.get_real_file = find_in_tmp

    plugin.assemble_fragments(dest_file.open(mode="w", encoding="utf-8"), src_dir)

    results = json.load(dest_file.open(mode="r", encoding="utf-8"))

    assert len(results) == 2
    assert results["one"] == "OVERLAY"
    assert results["two"] == "BASE"


def test_assemble_fragments_regexp(tmp_path):
    context = MockContext()
    context.task.async_val = False
    context.play_context.check_mode = False

    plugin = AssembleClusterTemplateAction(**vars(context))

    src_dir = tmp_path / "fragments"
    src_dir.mkdir()

    base = src_dir / "base.json"
    base.write_text(json.dumps(dict(one="BASE", two="BASE")))

    overlay = src_dir / "overlay.json"
    overlay.write_text(json.dumps(dict(one="OVERLAY")))

    ignored = src_dir / "ignored.json"
    ignored.write_text(json.dumps(dict(one="IGNORED")))

    dest_file = tmp_path / "dest.json"

    def find_in_tmp(fragment, decrypt):
        return os.path.join(src_dir, fragment)

    context.loader.get_real_file = find_in_tmp

    regexp = re.compile("^((?!ig).)*$")

    plugin.assemble_fragments(
        dest_file.open(mode="w", encoding="utf-8"),
        src_dir,
        regex=regexp,
    )

    results = json.load(dest_file.open(mode="r", encoding="utf-8"))

    assert len(results) == 2
    assert results["one"] == "OVERLAY"
    assert results["two"] == "BASE"


def test_assemble_fragments_malformed(tmp_path):
    context = MockContext()
    context.task.async_val = False
    context.play_context.check_mode = False

    plugin = AssembleClusterTemplateAction(**vars(context))

    src_dir = tmp_path / "fragments"
    src_dir.mkdir()

    base = src_dir / "base.json"
    base.write_text(json.dumps(dict(one="BASE", two="BASE")))

    overlay = src_dir / "overlay.json"
    overlay.write_text(json.dumps(dict(one="OVERLAY")))

    ignored = src_dir / "malformed.txt"
    ignored.write_text("BOOM")

    dest_file = tmp_path / "dest.json"

    def find_in_tmp(fragment, decrypt):
        return os.path.join(src_dir, fragment)

    context.loader.get_real_file = find_in_tmp

    with pytest.raises(AnsibleActionFail, match="JSON parsing error"):
        plugin.assemble_fragments(dest_file.open(mode="w", encoding="utf-8"), src_dir)
