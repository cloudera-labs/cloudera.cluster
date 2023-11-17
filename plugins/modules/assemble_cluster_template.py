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

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: assemble_cluster_template
short_description: Merge Cloudera Manager cluster template fragments
description:
  - Merge Cloudera Manager cluster template fragment files into a single JSON file.
  - The module supports C(check_mode).
author:
  - "Webster Mudge (@wmudge)"
  - "Ronald Suplina (@rsuplina)"
  - "Jim Enright (@jenright)"
  - "Andre Araujo (@asdaraujo)"
options:
  method:
    description:
      - HTTP method for the CM API endpoint path.
    type: str
    required: True
    choices:
        - DELETE
        - POST
        - PUT
  body:
    description:
      - HTTP body for the CM API endpoint call.
    type: dict
extends_documentation_fragment:
    - action_common_attributes
    - action_common_attributes.flow
    - action_common_attributes.files
    - decrypt
    - files
"""

EXAMPLES = r"""
---
"""

RETURN = r"""
---
"""

import os
import re
import tempfile

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native


class AssembleClusterTemplate(object):
    def __init__(self, module):
        self.module = module 
        
        # Set parameters
        self.src = self.module.params["src"]
        self.dest = self.module.params["dest"]
        self.backup = self.module.params["backup"]
        self.remote_src = self.module.params["remote_src"]
        self.regexp = self.module.params["regexp"]
        self.ignore_hidden = self.module.params["ignore_hidden"]

        self.unsafe_writes = self.module.params["unsafe_writes"]
        self.file_perms = self.module.load_file_common_arguments(self.module.params)

        # Initialize the return values
        self.output = {}
        self.changed = False

        # Initialize internal values
        self.compiled = None

        # Execute the logic
        self.process()

    def process_fragment(self, fh) -> bytes:
        updated = bytearray(fh.read())
        updated.extend("\n-------\n".encode())
        return updated

    def complete_assembly(self, assembled_file):
        pass

    def _assemble_fragments(self, assembled_file):
        # By file name sort order
        for f in sorted(os.listdir(self.src)):
            # Filter by regexp
            if self.compiled and not self.compiled.search(f):
                continue

            # Read and process the fragment
            fragment = os.path.join(self.src, f)
            if not os.path.isfile(fragment) or (
                self.ignore_hidden and os.path.basename(fragment).startswith(".")
            ):
                continue

            with open(fragment, "rb") as fragment_file:
                content = self.process_fragment(fragment_file)

            # Write the resulting bytes
            if content is not None:
                assembled_file.write(content)

        # Finalize any remaining assembly
        self.complete_assembly(assembled_file)

        # Close the assembled file handle
        assembled_file.close()

    def process(self):
        # Check source
        if not os.path.exists(self.src):
            self.module.fail_json(msg=f"Source, {self.src}, does not exist")
        elif not os.path.isdir(self.src):
            self.module.fail_json(msg=f"Source, {self.src}, is not a directory")

        # Compile filter expression
        if self.regexp is not None:
            try:
                self.compiled = re.compile(self.regexp)
            except re.error as e:
                self.module.fail_json(
                    msg=f"Regular expression, {self.regexp} is invalid: {to_native(e)}"
                )

        # Assemble fragments
        with tempfile.NamedTemporaryFile(
            dir=self.module.tmpdir, delete=False
        ) as assembled:           
            # Process fragments into temporary file
            self._assemble_fragments(assembled)

            # Confirm the assembled file is closed
            if not assembled.closed:
                self.module.fail_json(
                    msg=f"Assembled file, {assembled.name}, not closed after fragment processing"
                )

            # Generate hashes for assembled file
            assembled_sha1 = self.module.sha1(assembled.name)
            self.output.update(checksum=assembled_sha1)

            try:
                md5 = self.module.md5(assembled.name)
            except ValueError:
                md5 = None
            self.output.update(md5sum=md5)

            # Move to destination
            dest_sha1 = None
            if os.path.exists(self.dest):
                dest_sha1 = self.module.sha1(self.dest)

            if assembled_sha1 != dest_sha1:
                if self.backup and dest_sha1 is not None:
                    self.output.update(
                        backup_file=self.module.backup_local(self.dest)
                    )

                self.module.atomic_move(
                    assembled.name, self.dest, unsafe_writes=self.unsafe_writes
                )

                self.changed = True

        # Notify file permissions
        self.changed = self.module.set_fs_attributes_if_different(
            self.file_perms, self.changed
        )

        # Finalize output
        self.output.update(msg="OK")


def main():
    module = AnsibleModule(
        argument_spec=dict(
            src=dict(required=True, type="path"),
            dest=dict(required=True, type="path"),
            backup=dict(type="bool", default=False),
            remote_src=dict(type="bool", default=False),
            regexp=dict(type="str", aliases=["filter"]),
            ignore_hidden=dict(type="bool", default=True),
        ),
        add_file_common_args=True,
        supports_check_mode=True,
    )

    result = AssembleClusterTemplate(module)

    output = dict(
        changed=result.changed,
        **result.output,
    )

    module.exit_json(**output)


if __name__ == "__main__":
    main()
