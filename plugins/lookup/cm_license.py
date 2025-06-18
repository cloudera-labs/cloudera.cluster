# -*- coding: utf-8 -*-

# Copyright 2025 Cloudera, Inc.
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

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
    lookup: cm_license
    author: Webster Mudge (@wmudge) <wmudge@cloudera.com>
    short_description: Get the details of a Cloudera license
    description:
        - Parses and verifies the contents of a Cloudera license.
        - Returns the license details, including the computed C(password).
    options:
        _terms:
            description:
              - Path to the license file.
              - Will raise an error if multiple paths are specified.
              - If no C(contents) parameter is specified, the license file is read and parsed.
            type: list
            elements: path
            required: no
        contents:
            description: Contents of the license to parse.
            type: string
            required: no
        verify:
            description: Flag whether to verify the license signature.
            type: boolean
            required: no
            default: no
    requirements:
      - GnuPGP C(gpg) executable
      - python-gnupg
"""

EXAMPLES = """
- name: Parse a Cloudera license file
  ansible.builtin.debug:
    msg: "{{ lookup('cm_license', '/path/to/license_file.txt') }}"

- name: Parse a Cloudera license file, but enable verification
  ansible.builtin.debug:
    msg: "{{ lookup('cm_license', '/path/to/license_file.txt', verify=True) }}"

- name: Parse Cloudera license content
  ansible.builtin.debug:
    msg: "{{ lookup('cm_license', contents=body) }}"
  vars:
    body: |
      -----BEGIN PGP SIGNED MESSAGE-----
      Hash: SHA256

      {
        <license content>
      }
      ----BEGIN PGP SIGNATURE-----
      <PGP signature>
      -----END PGP SIGNATURE-----
"""

RETURN = """
  _value:
    description:
      - The contents of the license.
    type: dict
    contains:
      deactivation_date:
        description: Date of license deactivation.
        returned: always
      expiration_date:
        description: Date of license expiration.
        returned: always
      features:
        description: List of enabled features.
        type: list
        elements: str
        returned: when supported
      name:
        description: Name of the license.
        returned: always
      password:
        description: Computed password of the license.
        returned: always
      start_date:
        description: Date of license activation.
        returned: always
      uuid:
        description: Unique identifier of the license.
        returned: always
      version:
        description: Version of the license.
        returned: always
"""

import gnupg
import hashlib
import json

from ansible.errors import AnsibleLookupError
from ansible.module_utils.common.text.converters import to_native, to_bytes
from ansible.module_utils.common.dict_transformations import camel_dict_to_snake_dict
from ansible.plugins.lookup import LookupBase


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)

        contents = self.get_option("contents")

        if contents is not None:
            license = self.parse(body=contents)
        elif len(terms) == 1:
            license = self.parse(path=terms[0])
        elif len(terms) > 1:
            raise AnsibleLookupError(
                "Please specify a single path for the Cloudera license file."
            )
        else:
            raise AnsibleLookupError(
                "Please specify either the path to the Cloudera license or its contents in the 'contents' parameter."
            )

        msg = hashlib.sha256(to_bytes(license["name"] + license["uuid"]))

        license.update(password=msg.hexdigest()[:12])
        return [camel_dict_to_snake_dict(license)]

    def parse(self, path=None, body=None) -> dict:
        """Load the specified Cloudera license file.

        If the body parameter is specified, the file path will not be read.
        """

        try:
            if body is None:
                with open(path, "rb") as license:
                    license_content = license.read()
            else:
                license_content = to_bytes(body)
        except (IOError, OSError) as ex:
            raise AnsibleLookupError(to_native(ex))

        verified = gnupg.GPG().verify(license_content, extra_args=["-o", "-"])
        if not verified and self.get_option("verify"):
            raise AnsibleLookupError("License signature could not be verified.")

        try:
            return json.loads(verified.data)
        except json.JSONDecodeError as jex:
            raise AnsibleLookupError("Unable to parse license JSON", orig_exc=jex)
