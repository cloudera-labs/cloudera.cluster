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
    ClouderaManagerModule,
)
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
module: cluster
short_description: Enables cluster management, cluster creation, deletion, and unified control of all services for starting, stopping, or restarting.
description:
  - Create or delete cluster in Cloudera Manager
  - Start or stop all services inside the cluster
  - If template parameter is provided it searches for a template file, it will create cluster based on the template.
  - The search for the file starts at the root directory where the Ansible playbook is executed. By default, the template is expected to be placed inside the './files' directory.
author:
  - "Ronald Suplina (@rsuplina)"
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
"""

EXAMPLES = r"""
---

- name: Create an ECS Cluster
  cloudera.cluster.cm_cluster:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: "7180"
    clusterName: "OneNodeCluster"
    cluster_version: "1.5.1-b626.p0.42068229"
    cluster_type: "EXPERIENCE_CLUSTER"
    state: present



- name: Start services on a Cluster
  cloudera.cluster.cm_cluster:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    clusterName: "OneNodeCluster"
    state: start
    
- name: Create a cluster from Cluster Template
  cloudera.cluster.cm_cluster:
    host: example.cloudera.com
    username: "jane_smith"
    clusterName: "OneNodeCluster"
    password: "S&peR4Ec*re"
    port: "7180"
    template: "./files/cluster-template.json"
    add_repositories: "True"

- name: Delete a Cluster
  cloudera.cluster.cm_cluster:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    clusterName: "OneNodeCluster"
    state: absent

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


class ClouderaCluster(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaCluster, self).__init__(module)

        self.template = self.get_param("template")
        self.add_repositories = self.get_param("add_repositories")

        self.cluster_name = self.get_param("cluster_name")
        self.cluster_version = self.get_param("cluster_version")
        self.cluster_type = self.get_param("cluster_type")
        self.state = self.get_param("state")
        self.process()

    def check_required_params(self):
        if self.cluster_version is None and self.cluster_type is None:
            error_msg = "cluster_version, cluster_type"
            self.module.fail_json(msg=f"Missing required parameter(s): {error_msg}")
            
    @ClouderaManagerModule.handle_process
    def process(self):
        api_instance = ClouderaManagerResourceApi(self.api_client)
        cluster_api_instance = ClustersResourceApi(self.api_client)
        self.existing = None
        self.changed = False
        self.output = {}
        self.polling_interval = 30

        try:
            self.existing = cluster_api_instance.read_cluster(cluster_name=self.cluster_name).to_dict()
        except ApiException as ex:
            if ex.status != 404:
                raise ex
            

        template_contents = dict()
    
        if self.template:
            try:                
                with open(self.template, 'r') as file:
                    template_contents = json.load(file)
            except OSError as oe:
                self.module.fail_json(msg=f"Error reading file '{to_text(self.template)}'", err=to_native(oe)) 


        if self.state == "present" and self.template:
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

        if self.state in ['present'] and self.template is None:
            self.check_required_params()
            if self.existing:
                self.output = self.existing
            else:
                body = {"items": [{"name": self.cluster_name,"fullVersion": self.cluster_version,"clusterType": self.cluster_type }]}
                cluster_api_instance.create_clusters(body=body).to_dict()
                self.output=cluster_api_instance.read_cluster(cluster_name=self.cluster_name).to_dict()
                self.changed = True

        if self.state in ['absent']:
            if self.existing:
                self.output=cluster_api_instance.delete_cluster(cluster_name=self.cluster_name).to_dict()
                self.changed = True

        if self.state in ['start']:
            if self.existing:
                start_cluster=cluster_api_instance.start_command(cluster_name=self.cluster_name).to_dict()
                self.wait_for_command_state(command_id=start_cluster['id'],polling_interval=self.polling_interval)
            else:
                self.check_required_params()
                body = {"items": [{"name": self.cluster_name,"fullVersion": self.cluster_version,"clusterType": self.cluster_type }]}
                cluster_api_instance.create_clusters(body=body).to_dict()
                start_cluster=cluster_api_instance.start_command(cluster_name=self.cluster_name).to_dict()
                self.wait_for_command_state(command_id=start_cluster['id'],polling_interval=self.polling_interval)

            self.output=cluster_api_instance.read_cluster(cluster_name=self.cluster_name).to_dict()
            self.changed = True

        if self.state in ['stop']:
            if self.existing:
                stop_cluster = cluster_api_instance.stop_command(cluster_name=self.cluster_name).to_dict()
                self.wait_for_command_state(command_id=stop_cluster['id'],polling_interval=self.polling_interval)
            else:
                self.check_required_params()
                body = {"items": [{"name": self.cluster_name,"fullVersion": self.cluster_version,"clusterType": self.cluster_type }]}
                cluster_api_instance.create_clusters(body=body).to_dict()

            self.output=cluster_api_instance.read_cluster(cluster_name=self.cluster_name).to_dict()
            self.changed = True

        if self.state in ['restart']:
            if self.existing:
                restart_cluster = cluster_api_instance.restart_command(cluster_name=self.cluster_name).to_dict()
                self.wait_for_command_state(command_id=restart_cluster['id'],polling_interval=self.polling_interval)
            else:
                self.check_required_params()
                body = {"items": [{"name": self.cluster_name,"fullVersion": self.cluster_version,"clusterType": self.cluster_type }]}
                cluster_api_instance.create_clusters(body=body).to_dict()
                restart_cluster = cluster_api_instance.restart_command(cluster_name=self.cluster_name).to_dict()
                self.wait_for_command_state(command_id=restart_cluster['id'],polling_interval=self.polling_interval)

            self.output = cluster_api_instance.read_cluster(cluster_name=self.cluster_name).to_dict()
            self.changed = True
             

def main():
    module = ClouderaManagerModule.ansible_module(
           argument_spec=dict(
            cluster_name=dict(required=True, type="str"),
            cluster_version=dict(required=False, type="str"),
            cluster_type=dict(required=False, type="str"),
            state=dict(type='str', default='present', choices=['present','absent','stop','start','restart']),

            template=dict(type="path", aliases=["cluster_template"]),
            add_repositories=dict(type="bool", default=False),

                            ),
        supports_check_mode=True,
        required_together=[
        ('cluster_version', 'cluster_type'),
        ],
        )

    result = ClouderaCluster(module)

    changed = result.changed

    output = dict(
        changed=changed,
        cloudera_manager=result.output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
