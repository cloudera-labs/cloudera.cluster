#!/usr/bin/python
# -*- coding: utf-8 -*-

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

from __future__ import annotations

import configparser

from ansible.module_utils.common.dict_transformations import recursive_diff
from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.basic import AnsibleModule


class AnsibleModuleError(Exception):
    def __init__(self, results):
        self.results = results


def main():
    module = AnsibleModule(
        argument_spec=dict(
            config=dict(default="/etc/cloudera-scm-server/db.properties"),
            script=dict(required=True),
            type=dict(required=True, choices=["postgresql", "oracle", "mysql"]),
            host=dict(required=True),
            port=dict(required=True, type="int"),
            database=dict(required=True),
            username=dict(required=True),
            password=dict(required=True, no_log=True),
        )
    )

    # Handle parameters
    config = module.params["config"]
    script = module.params["script"]
    type = module.params["type"]
    host = module.params["host"]
    port = module.params["port"]
    database = module.params["database"]
    username = module.params["username"]
    password = module.params["password"]

    # Run precheck
    try:
        with open(config, "r") as f:
            contents = "[SCM]\n" + f.read()
        existing = configparser.ConfigParser()
        existing.optionxform = str
        existing.read_string(contents)
    except Exception as e:
        module.fail_json(
            msg="Error parsing Cloudera Manager db.properties", error=to_native(e)
        )

    incoming = {
        "com.cloudera.cmf.db.setupType": "EXTERNAL",
        "com.cloudera.cmf.db.type": type,
        "com.cloudera.cmf.db.host": host + ":" + str(port),
        "com.cloudera.cmf.db.name": database,
        "com.cloudera.cmf.db.user": username,
        "com.cloudera.cmf.db.password": password,
    }

    diff = recursive_diff(dict(existing["SCM"]), incoming)

    # Execute system command
    if diff is not None:
        args = f"{script} --host {host} --port {port} {type} {database} {username} {password}"

        (rc, stdout, stderr) = module.run_command(args, use_unsafe_shell=False)

        if rc != 0:
            module.fail_json(
                msg="Error preparing database.",
                rc=rc,
                stderr=stderr,
                stdout=stdout,
                stderr_lines=str(stderr).splitlines(),
                stdout_lines=str(stdout).splitlines(),
            )
        else:
            module.exit_json(
                changed=True,
                msg="Database preparation succeeded.",
                stdout=stdout,
                stdout_lines=str(stdout).splitlines(),
            )
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
