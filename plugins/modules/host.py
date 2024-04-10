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

from cm_client import ClustersResourceApi
from cm_client import HostsResourceApi
from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: host
short_description: Manage hosts within Cloudera Manager
description:
  - Create, delete, attach or detach a host instance.
author:
  - "Ronald Suplina (@rsuplina)"
requirements:
  - cm_client
"""
DOCUMENTATION = r"""
---
module: host
short_description: Manage hosts within Cloudera Manager
description:
  - Allows for the management of hosts within the Cloudera Manager.
  - It provides functionalities to create, delete, attach, or detach host instance from a cluster.
author:
  - "Ronald Suplina (@rsuplina)"
requirements:
  - cm_client
"""

EXAMPLES = r"""
---
- name: Create a host
  cloudera.cluster.host:
    host: "example.cloudera.host"
    username: "will_jordan"
    password: "S&peR4Ec*re"
    host_name: "Ecs_node_01"
    host_ip: "10.9.8.7"
    state: "present"
- name: Attach a host to the Cluster
  cloudera.cluster.host:
    host: "example.cloudera.host"
    username: "will_jordan"
    cluster_name: "Base_Edge2AI_Node"
    password: "S&peR4Ec*re"
    host_name: "Ecs_node_01"
    state: "attach"
- name: Detach a host to the Cluster
  cloudera.cluster.host:
    host: "example.cloudera.host"
    username: "will_jordan"
    cluster_name: "Base_Edge2AI_Node"
    password: "S&peR4Ec*re"
    host_name: "Ecs_node_01"
    state: "detach"
"""

RETURN = r"""
---
cloudera_manager:
    description: Details about Cloudera Manager Host
    type: dict
    contains:
        clusterRef:
            description: A reference to the enclosing cluster.
            type: str
            returned: optional
        commissionState:
            description: Represents the Commission state of an entity.
            type: str
            returned: optional
        distribution:
            description: OS distribution details.
            type: dict
            returned: optional
        entity_status:
            description: The single value used by the Cloudera Manager UI to represent the status of the entity.
            type: str
            returned: optional
        health_checks:
            description: Represents a result from a health test performed by Cloudera Manager for an entity.
            type: list
            returned: optional
        health_summary:
            description: The summary status of health check.
            type: str
            returned: optional
        host_id:
            description: A unique host identifier. This is not the same as the hostname (FQDN). It is a distinct value that remains the same even if the hostname changes.
            type: str
            returned: optional
        host_url:
            description: A URL into the Cloudera Manager web UI for this specific host.
            type: str
            returned: optional
        hostname:
            description: The hostname. This field is not mutable after the initial creation.
            type: str
            returned: optional
        ip_address:
            description: The host IP address. This field is not mutable after the initial creation.
            type: str
            returned: optional
        last_heartbeat:
            description: Time when the host agent sent the last heartbeat.
            type: str
            returned: optional
        maintenance_mode:
            description: Maintance mode of Cloudera Manager Service.
            type: bool
            returned: optional
        maintenance_owners:
            description: List of Maintance owners for Cloudera Manager Service.
            type: list
            returned: optional
        num_cores:
            description: The number of logical CPU cores on this host.
            type: number
            returned: optional
        numPhysicalCores:
            description: The number of physical CPU cores on this host.
            type: number
            returned: optional
        rack_id:
            description: The rack ID for this host.
            type: str
            returned: optional
        role_refs:
            description: The list of roles assigned to this host.
            type: list
            returned: optional
        tags:
            description: Tags associated with the host.
            type: list
            returned: optional
        total_phys_mem_bytes:
            description: he amount of physical RAM on this host, in bytes.
            type: str
            returned: optional
"""


class ClouderaHost(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaHost, self).__init__(module)

        # Initialize the return values
        self.host_name = self.get_param("host_name")
        self.cluster_name = self.get_param("cluster_name")
        self.host_ip = self.get_param("host_ip")
        self.state = self.get_param("state")
        # Execute the logic
        self.process()

    def check_required_host_id_param(self):
        if self.host_ip is None:
            error_msg = "host_ip"
            self.module.fail_json(msg=f"Missing required parameter: {error_msg}")

    def check_required_cluster_name_param(self):
        if self.cluster_name is None:
            error_msg = "cluster_name"
            self.module.fail_json(msg=f"Missing required parameter: {error_msg}")

    @ClouderaManagerModule.handle_process
    def process(self):

        cluster_api_instance = ClustersResourceApi(self.api_client)
        host_api_instance = HostsResourceApi(self.api_client)
        self.host_output = {}
        self.changed = False
        existing = None

        try:
            hosts = host_api_instance.read_hosts().to_dict()
            for host in hosts['items']:
                if self.host_name == host['hostname']:
                    host_id = host['host_id']
                    existing = host_api_instance.read_host(host_id=host_id).to_dict()
                    break
                
        except ApiException as ex:
            if ex.status != 404:
                raise ex  
            
        if self.state in ['present']:
            if existing:
                self.host_output = existing
            else:
                self.check_required_host_id_param()
                body = {"items": [{"hostname": self.host_name,"ipAddress": self.host_ip }]}
                create_host = host_api_instance.create_hosts(body=body).to_dict()
                self.host_output = host_api_instance.read_host(host_id=create_host['items'][0]['host_id']).to_dict()
                self.changed = True

        if self.state in ['absent']:
            if existing:
                self.host_output = host_api_instance.delete_host(host_id=existing['host_id']).to_dict()
                self.changed = True

        if self.state in ['attach','detach']:
            self.check_required_cluster_name_param()
            try:
                cluster_api_instance.read_cluster(cluster_name=self.cluster_name).to_dict()
            except ApiException as ex:
                if ex.status == 404:
                    self.module.fail_json(msg=f"Cluster does not exist:  {self.cluster_name}")

        if self.state in ['attach']:
            if existing:
                try:
                    body = {"items": [{"hostId": existing['host_id'],"hostname": self.host_name }]}
                    cluster_api_instance.add_hosts(cluster_name=self.cluster_name,body=body).to_dict()
                    self.changed = True
                except ApiException as ex:
                    if ex.status == 400:
                        pass
                self.host_output = host_api_instance.read_host(host_id=host_id).to_dict()
            else:
                self.check_required_host_id_param()
                body = {"items": [{"hostname": self.host_name,"ipAddress": self.host_ip }]}
                create_host = host_api_instance.create_hosts(body=body).to_dict()
                body = {"items": [{"hostId": create_host['items'][0]['host_id'],"hostname": self.host_name }]}
                add_host=cluster_api_instance.add_hosts(cluster_name=self.cluster_name,body=body).to_dict()
                self.host_output = host_api_instance.read_host(host_id=add_host['items'][0]['host_id']).to_dict()
                self.changed = True

        if self.state in ['detach']:
            if existing and existing.get('cluster_ref') and existing['cluster_ref'].get('cluster_name'):
                    cluster_api_instance.remove_host(cluster_name=existing['cluster_ref']['cluster_name'],host_id=existing['host_id']).to_dict()
                    self.host_output = host_api_instance.read_host(host_id=host_id).to_dict()
                    self.changed = True

  
def main():
    module = ClouderaManagerModule.ansible_module(
           argument_spec=dict(
            host_name=dict(required=True, type="str"),
            cluster_name=dict(required=False, type="str"),
            host_ip=dict(required=False, type="str"),
            state=dict(type='str', default='present', choices=['present','absent','attach','detach']),
                          ),
        supports_check_mode=True)

    result = ClouderaHost(module)

    changed = result.changed

    output = dict(
        changed=changed,
        cloudera_manager=result.host_output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)

if __name__ == "__main__":
    main()
