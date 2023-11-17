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
  - Merge multiple Cloudera Manager cluster template files into a single cluster template file.
  - Often a cluster template file is composed of several services, host templates,
    and other parameters from multiple sources and/or configurations. 
    M(cloudera.cluster.assemble_cluster_template) will take a directory of 
    cluster template configuration files that can be local or have already been
    transferred to the system and merge them together to produce a single,
    composite cluster template configuration file.
  - Files are merged in string sorting order.
version_added: "4.2.0"
author:
  - "Webster Mudge (@wmudge)"
  - "Ronald Suplina (@rsuplina)"
  - "Jim Enright (@jenright)"
  - "Andre Araujo (@asdaraujo)"
options:
  src:
    description:
      - An already existing directory of cluster template files.
      - TODO Local or remote
    type: path
    required: True
    aliases:
      - cluster_template_src
  dest:
    description:
      - A file to create using the merger of all of the cluster template files.
    type: path
    required: True
    aliases:
      - cluster_template
  backup:
    description:
      - Create a backup file if V(true).
      - The backup file name includes a timestamp.
    type: bool
    default: False
  remote_src:
    description:
      - Flag to control the location of the cluster template configuration source files.
      - If V(false), search for I(src) on the controller.
      - If V(true), search for I(src) on the remote/target.
    type: bool
    default: False
  regexp:
    description:
      - Merge files only if the given regular expression matches the filename.
      - If not set, all files within C(src) are merged.
      - Every V(\\) (backslash) must be escaped as V(\\\\) to conform to YAML syntax.
      - See L(Python regular expressions,https://docs.python.org/3/library/re.html).
    type: str
    aliases:
      - filter
  ignore_hidden:
    description:
      - Flag whether to include files that begin with a '.'.
    type: bool
    default: True
attributes:
  action:
    support: full
  async:
    support: none
  bypass_host_loop:
    support: none
  check_mode:
    support: none
  diff_mode:
    support: full
  platform:
    platforms: posix
  safe_file_operations:
    support: full
  vault:
    support: full
seealso:
  - module: ansible.builtin.assemble
  - module: ansible.builtin.copy
  - module: ansible.builtin.template
  - module: ansible.windows.win_copy
extends_documentation_fragment:
  - action_common_attributes
  - action_common_attributes.flow
  - action_common_attributes.files
  - decrypt
  - files
"""

EXAMPLES = r"""
---
- name: Assemble a cluster template from files (on the controller)
  cloudera.cluster.assemble_cluster_template:
    src: examples
    dest: /opt/cloudera/cluster-template.json

- name: Assemble a cluster template from selected files (on the controller)
  cloudera.cluster.assemble_cluster_template:
    src: examples
    dest: /opt/cloudera/cluster-template.json
    regexp: "base|nifi"
    
- name: Assemble a cluster template from files on the target host
  cloudera.cluster.assemble_cluster_template:
    src: /tmp/examples
    dest: /opt/cloudera/cluster-template.json
    remote_src: yes
"""

RETURN = r"""#"""

import json
import os
import re
import tempfile

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native


class AssembleClusterTemplate(object):
    MERGED = {}
    IDEMPOTENT_IDS = ["refName", "name", "clusterName", "hostName", "product"]
    UNIQUE_IDS = ["repositories"]

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
                    self.module.warn(
                        f"Objects with distinct IDs should not be merged: {crumb}"
                    )
                continue

            if key not in base:
                base[key] = value
            elif not self.update_object(base[key], value, crumb) and base[key] != value:
                self.module.warn(
                    f"Value being overwritten for key [{crumb}]; Old: [{base[key]}], New: [{value}]"
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

    def assemble_fragments(self, assembled_file):
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

            with open(fragment, "r", encoding="utf-8") as fragment_file:
                try:
                    self.update_object(self.MERGED, json.loads(fragment_file.read()))
                except json.JSONDecodeError as e:
                    self.module.fail_json(
                        msg=f"JSON parsing error: {to_text(e.msg)}", error=to_native(e)
                    )

        # Write out the final assembly
        json.dump(self.MERGED, assembled_file, indent=2, sort_keys=False)

        # Close the assembled file handle; will not delete for atomic_move
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

        # Assemble the src files into output file
        # No deletion on close; atomic_move "removes" the file
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=self.module.tmpdir, delete=False
        ) as assembled:
            # Process fragments into temporary file
            self.assemble_fragments(assembled)

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
                    self.output.update(backup_file=self.module.backup_local(self.dest))

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
            src=dict(required=True, type="path", aliases=["cluster_template_src"]),
            dest=dict(required=True, type="path", aliases=["cluster_template"]),
            backup=dict(type="bool", default=False),
            remote_src=dict(type="bool", default=False),
            regexp=dict(type="str", aliases=["filter"]),
            ignore_hidden=dict(type="bool", default=True),
        ),
        add_file_common_args=True,
        supports_check_mode=False,
    )

    result = AssembleClusterTemplate(module)

    output = dict(
        changed=result.changed,
        **result.output,
    )

    module.exit_json(**output)


if __name__ == "__main__":
    main()
