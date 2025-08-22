#!/usr/bin/python
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

DOCUMENTATION = r"""
module: cm_trial_license
short_description: Activate the trial license of Cloudera Manager
description:
  - Checking if the trial license is already activated.
  - Activating the trial license if it is not already activated.
  - Return information about the trial license.
author:
  - "Ronald Suplina (@rsuplina)"
version_added: "4.4.0"
requirements:
  - cm_client
"""

EXAMPLES = r"""
- name: Activate the trial license of Cloudera Manager
  cloudera.cluster.cm_trial_license:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
"""

RETURN = r"""
cloudera_manager:
    description: Details about trial license
    type: dict
    contains:
        owner:
            description: Type of the license
            type: str
            returned: optional
        uuid:
            description: Unique ID of trial license
            type: bool
            returned: optional
        expiration:
            description: Expiration date of trial license
            type: str
            returned: optional
        features:
            description: List of features within the trial license
            type: list
            returned: optional
        deactivation_date:
            description: Date until trial is active
            type: str
            returned: optional
        start_date:
            description: trial activation date
            type: str
            returned: optional
"""

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from cm_client.rest import ApiException
from cm_client import ClouderaManagerResourceApi


class ClouderaTrial(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaTrial, self).__init__(module)
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        if not self.module.check_mode:
            api_instance = ClouderaManagerResourceApi(self.api_client)

            try:
                get_trial_state_request = api_instance.read_license().to_dict()

                if get_trial_state_request:
                    self.cm_trial_output = get_trial_state_request
                    self.changed = False

            except ApiException as e:
                if e.status == 404:
                    api_instance.begin_trial()
                    get_trial_state_request = api_instance.read_license().to_dict()
                    self.cm_trial_output = get_trial_state_request
                    self.changed = True


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(),
        supports_check_mode=True,
    )

    result = ClouderaTrial(module)

    changed = result.changed

    output = dict(
        changed=changed,
        cloudera_manager=result.cm_trial_output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
