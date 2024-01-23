# Copyright 2024 Cloudera, Inc. All Rights Reserved.
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

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from cm_client.rest import ApiException
from cm_client import ClouderaManagerResourceApi
from cm_client import ClustersResourceApi
import json

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: cm_import_cluster_template
short_description: Create a cluster based on the provided cluster template
description:
  - Searches for a template file.
  - The search for the file starts at the root directory where the Ansible playbook is executed. By default, the template is expected to be placed inside the './files' directory.
  - Imports the template file and uses it to create the cluster.
  - This module ensures that the cluster is created according to the specified template.
author:
  - "Ronald Suplina (@rsuplina)"
options:
  template:
    description:
      - Path to template file which defines the cluster
    type: path
    elements: str
    required: True
  add_repositories:
    description:
      - Install parcel repositories in parcel directory
    type: bool
    required: False
    default: False
requirements:
  - cm_client
"""

EXAMPLES = r"""
---
- name: Create a cluster on Cloudera Manager host
  cloudera.cluster.cm_import_cluster_template:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: "7180"
    template: "./files/cluster-template.json"

- name: Create a cluster and install the repositories defined in template
  cloudera.cluster.cm_import_cluster_template:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: "7180"
    template: "./files/cluster-template.json"
    add_repositories: "True"
"""

RETURN = r"""
---
cloudera_manager:
    description: Details about Cloudera Manager Cluster
    type: dict
    contains:
        cluster_type:
            description: The type of cluster created from template.
            type: str
            returned: optional
        cluster_url:
            description: Url of Cloudera Manager cluster.
            type: str
            returned: optional
        display_name:
            description: The name of the cluster displayed on the site.
            type: str
            returned: optional
        entity_status:
            description: Health status of the cluster.
            type: str
            returned: optional
        full_version:
            description: Version of the cluster installed.
            type: str
            returned: optional
        hosts_url:
            description: Url of all the hosts on which cluster is installed.
            type: str
            returned: optional
        maintenance_mode:
            description: Maintance mode of Cloudera Manager Cluster.
            type: bool
            returned: optional
        maintenance_owners:
            description: List of Maintance owners for Cloudera Manager Cluster.
            type: list
            returned: optional
        name:
            description: The name of the cluster created.
            type: str
            returned: optional
        tags:
            description: List of tags for Cloudera Manager Cluster.
            type: list
            returned: optional
        uuid:
            description: Unique ID of created cluster
            type: bool
            returned: optional
"""


class ClusterTemplate(ClouderaManagerModule):
    def __init__(self, module):
        super(ClusterTemplate, self).__init__(module)
        self.template = self.get_param("template")
        self.add_repositories = self.get_param("add_repositories")
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        
        try:
            api_instance = ClouderaManagerResourceApi(self.api_client)
            cluster_api_instance = ClustersResourceApi(self.api_client)

            with open(self.template, 'r') as file:
                template_json = json.load(file)
            if self.add_repositories:
                import_template_request = api_instance.import_cluster_template(add_repositories=True,body=template_json).to_dict()
            else:
                import_template_request = api_instance.import_cluster_template(body=template_json).to_dict()

            command_id = import_template_request['id']

            self.wait_for_command_state(command_id=command_id,polling_interval=60)
            
            self.cm_cluster_template_output = cluster_api_instance.read_clusters().to_dict()
            self.changed = True
            self.file_not_found = False

        except ApiException as e:
            if e.status == 400:
                self.cm_cluster_template_output = json.loads(e.body)
                self.changed = False
                self.file_not_found = False

        except FileNotFoundError:
            self.cm_cluster_template_output = (f"Error: File '{self.template}' not found.")
            self.file_not_found = True 
def main():
    module = ClouderaManagerModule.ansible_module(
        
        argument_spec=dict(
            template=dict(required=True, type="path"),
            add_repositories=dict(required=False, type="bool", default=False),
        ),
          supports_check_mode=False
          )

    result = ClusterTemplate(module) 
    
    if result.file_not_found:
        module.fail_json(msg=str(result.cm_cluster_template_output))

    changed = result.changed

    output = dict(
        changed=changed,
        cloudera_manager=result.cm_cluster_template_output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
