#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2025 Cloudera, Inc.
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

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClusterTemplate,
)


class ActionModule(ActionBase):
    TRANSFERS_FILES = True

    def __init__(
        self,
        task,
        connection,
        play_context,
        loader,
        templar,
        shared_loader_obj,
    ):
        super().__init__(
            task,
            connection,
            play_context,
            loader,
            templar,
            shared_loader_obj,
        )
        self.TEMPLATE = ClusterTemplate(
            warn_fn=self._display.warning,
            error_fn=self._display.error,
        )
        self.MERGED = {}

    def assemble_fragments(
        self,
        assembled_file,
        src_path,
        regex=None,
        ignore_hidden=True,
        decrypt=True,
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
                    if not self.MERGED:
                        self.MERGED = json.loads(fragment_file.read())
                    else:
                        self.TEMPLATE.merge(
                            self.MERGED,
                            json.loads(fragment_file.read()),
                        )
                except json.JSONDecodeError as e:
                    raise AnsibleActionFail(
                        message=f"JSON parsing error for file, {fragment}: {to_text(e.msg)}",
                        obj=to_native(e),
                    )

        # Write out the final assembly
        json.dump(self.MERGED, assembled_file, indent=2, sort_keys=False)

        # Flush the assembled file handle
        assembled_file.flush()

    def run(self, tmp=None, task_vars=None):
        self._supports_check_mode = False

        result = super(ActionModule, self).run(tmp, task_vars)

        del tmp  # legacy
        if task_vars is None:
            task_vars = dict()

        # Handle aliases
        src = self._task.args.get("src", None)
        if src is None:
            src = self._task.args.get("cluster_template_src", None)

        dest = self._task.args.get("dest", None)
        if dest is None:
            dest = self._task.args.get("cluster_template")

        regexp = self._task.args.get("regexp", None)
        if regexp is None:
            regexp = self._task.args.get("filter", None)
        if regexp is None:
            regexp = self._task.args.get("regex", None)

        remote_src = boolean(self._task.args.get("remote_src", False))
        follow = boolean(self._task.args.get("follow", False))
        ignore_hidden = boolean(self._task.args.get("ignore_hidden", True))
        decrypt = self._task.args.pop("decrypt", True)

        try:
            if src is None or dest is None:
                raise AnsibleActionFail("Both 'src' and 'dest' are required")

            # If src files are on the remote host, run the module
            if boolean(remote_src, strict=False):
                result.update(
                    self._execute_module(
                        module_name="cloudera.cluster.assemble_cluster_template",
                        task_vars=task_vars,
                    ),
                )
                raise _AnsibleActionDone()
            else:
                try:
                    src = self._find_needle("files", src)
                except AnsibleError as e:
                    raise AnsibleActionFail(to_native(e))

            if not os.path.isdir(src):
                raise AnsibleActionFail(f"Source, {src}, is not a directory")

            # Compile the regexp
            compiled = None
            if regexp is not None:
                try:
                    compiled = re.compile(regexp)
                except re.error as e:
                    raise AnsibleActionFail(
                        message=f"Regular expression, {regexp}, is invalid: {to_native(e)}",
                    )

            # Assemble the src files into output file
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=C.DEFAULT_LOCAL_TMP,
            ) as assembled:
                self.assemble_fragments(
                    assembled,
                    src,
                    regex=compiled,
                    ignore_hidden=ignore_hidden,
                    decrypt=decrypt,
                )

                # Gather the checksums for assembled file and destination file
                assembled_checksum = checksum_s(assembled.name)

                dest = self._remote_expand_user(dest)
                dest_stat = self._execute_remote_stat(
                    dest,
                    all_vars=task_vars,
                    follow=follow,
                )

                # Prepare the task arguments for the called submodules
                submodule_args = self._task.args.copy()

                # Purge non-submodule arguments
                for o in [
                    "cluster_template_src",
                    "cluster_template",
                    "remote_src",
                    "regexp",
                    "filter",
                    "ignore_hidden",
                    "decrypt",
                ]:
                    submodule_args.pop(o, None)

                # Update the 'dest' arg
                submodule_args.update(dest=dest)

                if assembled_checksum != dest_stat["checksum"]:
                    diff = {}

                    if self._task.diff:
                        diff = self._get_diff_data(dest, assembled.name, task_vars)

                    # Define a temporary remote path for the remote copy
                    remote_path = self._connection._shell.join_path(
                        self._connection._shell.tmpdir,
                        "assembled_cluster_template",
                    )

                    # Transfer the file to the remote path
                    transfered = self._transfer_file(assembled.name, remote_path)

                    # Update the file permissions on the remote file
                    self._fixup_perms2((self._connection._shell.tmpdir, remote_path))

                    # Update the 'src' arg with the temporary remote file
                    submodule_args.update(
                        dict(
                            src=transfered,
                        ),
                    )

                    # Execute the copy
                    copy = self._execute_module(
                        module_name="ansible.legacy.copy",
                        module_args=submodule_args,
                        task_vars=task_vars,
                    )

                    if diff:
                        copy.update(diff=diff)

                    result.update(copy)
                else:
                    # Gather details on the existing file
                    file = self._execute_module(
                        module_name="ansible.legacy.file",
                        module_args=submodule_args,
                        task_vars=task_vars,
                    )

                    result.update(file)
        except AnsibleAction as e:
            result.update(e.result)
        finally:
            self._remove_tmp_path(self._connection._shell.tmpdir)

        return result
