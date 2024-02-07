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

from ansible.module_utils.common.text.converters import to_text, to_native

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule, ClusterTemplate
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
module: cm_cluster
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
  clusterName:
    description:
      - Name of Cloudera Manager Cluster
    type: str
    required: False
    default: False
requirements:
  - cm_client
"""

EXAMPLES = r"""
---
- name: Create a cluster on Cloudera Manager host
  cloudera.cluster.cm_cluster:
    host: example.cloudera.com
    username: "jane_smith"
    clusterName: "OneNodeCluster"
    password: "S&peR4Ec*re"
    port: "7180"
    template: "./files/cluster-template.json"

- name: Create a cluster and install the repositories defined in template
  cloudera.cluster.cm_cluster:
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


class ClusterModule(ClouderaManagerModule):
    def __init__(self, module):
        super(ClusterModule, self).__init__(module)
        
        self.template = self.get_param("template")
        self.add_repositories = self.get_param("add_repositories")
        self.cluster_name = self.get_param("name")
        self.state = self.get_param("state")
        
        self.changed = False
        self.output = dict()
        
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        
        api_instance = ClouderaManagerResourceApi(self.api_client)
        cluster_api_instance = ClustersResourceApi(self.api_client)
    
        template_contents = dict()
    
        if self.template:
            try:                
                with open(self.template, 'r') as file:
                    template_contents = json.load(file)
            except OSError as oe:
                self.module.fail_json(msg=f"Error reading file '{to_text(self.template)}'", err=to_native(oe)) 
            # Need to catch malformed JSON, etc.

        if not self.cluster_name:
            if template_contents:
                self.cluster_name = template_contents['instantiator']['clusterName']
            else:
                self.module.fail_json(msg="No cluster name found in template.")
    
        try:
            self.existing = cluster_api_instance.read_cluster(cluster_name=self.cluster_name).to_dict()
        except ApiException:
            self.existing = dict()

        if self.state == "present":
            if self.existing:
                pass
                # Reconcile the existing vs. the incoming values into a set of diffs
                # then process via the PUT /clusters/{clusterName} endpoint
            else:
                payload = dict()
                    
                # Construct import template payload from the template and/or explicit parameters
                explicit_params = dict()
                
                # Set up 'instantiator' parameters
                explicit_params.update(instantiator=dict(
                    clusterName=self.cluster_name
                ))
                
                if template_contents:
                    TEMPLATE = ClusterTemplate(warn_fn=self.module.warn, error_fn=self.module.fail_json)
                    TEMPLATE.merge(template_contents, explicit_params)
                    payload.update(body=template_contents)
                else:
                    payload.update(body=explicit_params)
                        
                # Update to include repositories
                if self.add_repositories:
                    payload.update(add_repositories=True)              
                
                # Execute the import
                if not self.module.check_mode:
                    self.changed = True
                    import_template_request = api_instance.import_cluster_template(**payload).to_dict()

                command_id = import_template_request['id']
                self.wait_for_command_state(command_id=command_id,polling_interval=60)
                
                # Retrieve the newly-minted cluster
                self.output = cluster_api_instance.read_cluster(cluster_name=self.cluster_name).to_dict()
        elif self.state == "absent":
            if self.existing:
                pass
                # Delete the cluster via DELETE /clusters/{clusterName}
        else:
            self.module.fail_json(msg=f"Invalid state, ${self.state}")


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            template=dict(type="path", aliases=["cluster_template"]),
            add_repositories=dict(type="bool", default=False),
            name=dict(aliases=["cluster_name"]),
            state=dict(default="present", choices=["present", "absent"])
        ),
        required_one_of=[
            ["name", "template"]
        ],
        supports_check_mode=True
    )

    result = ClusterModule(module) 

    output = dict(
        changed=result.changed,
        cloudera_manager=result.existing,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
