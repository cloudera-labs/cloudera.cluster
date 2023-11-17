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

import json
import os
import re
import tempfile

from ansible import constants as C
from ansible.errors import (
    AnsibleAction,
    AnsibleError,
    _AnsibleActionDone,
    AnsibleActionFail,
)
from ansible.module_utils.common.text.converters import to_native, to_text
from ansible.module_utils.parsing.convert_bool import boolean
from ansible.plugins.action import ActionBase
from ansible.utils.hashing import checksum_s


class ActionModule(ActionBase):
    TRANSFERS_FILES = True

    MERGED = {}
    IDEMPOTENT_IDS = ["refName", "name", "clusterName", "hostName", "product"]
    UNIQUE_IDS = ["repositories"]

    def update_object(self, base, template, breadcrumbs=""):
        if isinstance(base, dict) and isinstance(template, dict):
            self.update_dict(base, template, breadcrumbs)
            return True
        elif isinstance(base, list) and isinstance(template, list):
            self.update_list(base, template, breadcrumbs)
            return True
        return False

    def update_dict(self, base, template, breadcrumbs=""):
        for key, value in template.items():
            crumb = breadcrumbs + "/" + key

            if key in self.IDEMPOTENT_IDS:
                if base[key] != value:
                    self._display.error(
                        "Objects with distinct IDs should not be merged: " + crumb
                    )
                continue

            if key not in base:
                base[key] = value
            elif not self.update_object(base[key], value, crumb) and base[key] != value:
                self._display.warning(
                    f"Value being overwritten for key [{crumb}]], Old: [{base[key]}], New: [{value}]"
                )
                base[key] = value

            if key in self.UNIQUE_IDS:
                base[key] = list(set(base[key]))

    def update_list(self, base, template, breadcrumbs=""):
        for item in template:
            if isinstance(item, dict):
                for attr in self.IDEMPOTENT_IDS:
                    if attr in item:
                        idempotent_id = attr
                        break
                else:
                    idempotent_id = None
                if idempotent_id:
                    namesake = [
                        i for i in base if i[idempotent_id] == item[idempotent_id]
                    ]
                    if namesake:
                        # LOG.warn("List item being replaced, Old: [%s], New: [%s]", namesake[0], item)
                        self.update_dict(
                            namesake[0],
                            item,
                            breadcrumbs
                            + "/["
                            + idempotent_id
                            + "="
                            + item[idempotent_id]
                            + "]",
                        )
                        continue
            base.append(item)
        base.sort(key=lambda x: json.dumps(x, sort_keys=True))

    def _assemble_fragments(
        self, assembled_file, src_path, regex=None, ignore_hidden=True, decrypt=True
    ):
        # By file name sort order
        for f in (
            to_text(p, errors="surrogate_or_strict")
            for p in sorted(os.listdir(src_path))
        ):
            # Filter by regexp
            if regex and not regex.search(f):
                continue

            # Read and process the fragment
            fragment = os.path.join(src_path, f)
            if not os.path.isfile(fragment) or (
                ignore_hidden and os.path.basename(fragment).startswith(".")
            ):
                continue

            with open(
                self._loader.get_real_file(fragment, decrypt=decrypt),
                "r",
                encoding="utf-8",
            ) as fragment_file:
                try:
                    self.update_object(self.MERGED, json.loads(fragment_file.read()))
                except json.JSONDecodeError as e:
                    raise AnsibleActionFail(
                        message=f"{to_text(e.msg)}", obj=to_native(e)
                    )

        # Write out the final assembly
        json.dump(self.MERGED, assembled_file, indent=2, sort_keys=False)

        # Close the assembled file handle
        assembled_file.close()

    def run(self, tmp=None, task_vars=None):
        self._supports_check_mode = False

        result = super(ActionModule, self).run(tmp, task_vars)

        del tmp  # legacy
        if task_vars is None:
            task_vars = dict()

        src = self._task.args.get("src", None)
        dest = self._task.args.get("dest", None)
        remote_src = self._task.args.get("remote_src", False)
        regexp = self._task.args.get("regexp", None)
        follow = self._task.args.get("follow", False)
        ignore_hidden = boolean(self._task.args.get("ignore_hidden", True))
        decrypt = self._task.args.pop("decrypt", True)

        try:
            if src is None or dest is None:
                raise AnsibleActionFail("src and dest are required")

            if boolean(remote_src, strict=False):
                result.update(
                    self._execute_module(
                        module_name="cloudera.cluster.assemble_cluster_template",
                        task_vars=task_vars,
                    )
                )
                raise _AnsibleActionDone()
            else:
                try:
                    src = self._find_needle("files", src)
                except AnsibleError as e:
                    raise AnsibleActionFail(to_native(e))

            if not os.path.isdir(src):
                raise AnsibleActionFail(f"Source, {src}, is not a directory")

            compiled = None
            if regexp is not None:
                compiled = re.compile(regexp)

            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=C.DEFAULT_LOCAL_TMP, delete=False
            ) as assembled:
                self._assemble_fragments(
                    assembled,
                    src,
                    regex=compiled,
                    ignore_hidden=ignore_hidden,
                    decrypt=decrypt,
                )

            assembled_checksum = checksum_s(assembled.name)
            dest = self._remote_expand_user(dest)
            dest_stat = self._execute_remote_stat(
                dest, all_vars=task_vars, follow=follow
            )

            new_module_args = self._task.args.copy()

            # Purge cloudera.cluster.assemble_cluster_template-specific options
            for o in ["remote_src", "regexp", "filter", "ignore_hidden", "decrypt", ]:
                new_module_args.pop(o, None)

            new_module_args.update(dest=dest)

            diff = {}
            if assembled_checksum != dest_stat["checksum"]:
                if self._task.diff:
                    diff = self._get_diff_data(dest, assembled.name, task_vars)

                remote_path = self._connection._shell.join_path(
                    self._connection._shell.tmpdir, "assembled_cluster_template"
                )
                transfered = self._transfer_file(assembled.name, remote_path)

                self._fixup_perms2((self._connection._shell.tmpdir, remote_path))

                new_module_args.update(
                    dict(
                        src=transfered,
                    )
                )

                copy = self._execute_module(
                    module_name="ansible.legacy.copy",
                    module_args=new_module_args,
                    task_vars=task_vars,
                )

                if diff:
                    copy.update(diff=diff)
                result.update(copy)
            else:
                file = self._execute_module(
                    module_name="ansible.legacy.file",
                    module_args=new_module_args,
                    task_vars=task_vars,
                )
                result.update(file)
        except AnsibleAction as e:
            result.update(e.result)
        finally:
            self._remove_tmp_path(self._connection._shell.tmpdir)

        return result
