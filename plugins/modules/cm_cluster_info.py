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

from ansible.module_utils.basic import to_native
from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from cm_client.rest import ApiException
from cm_client import ClustersResourceApi

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: cm_cluster_info
short_description: Retrieve details about one or more clusters
description:
  - Retrieves details about one or more clusters managed by Cloudera Manager
author:
  - "Ronald Suplina (@rsuplina)"
options:
  name:
    description:
      - Name of Cloudera Manager cluster.
      - This parameter specifies the name of the cluster from which data will be gathered.
    type: str
    required: False
requirements:
  - cm_client
"""

EXAMPLES = r"""
---
- name: Get information about the cluster
  cloudera.cluster.cm_cluster_info:
    host: example.cloudera.com
    username: "jane_smith"
    name: "OneNodeCluster"
    password: "S&peR4Ec*re"
    port: "7180"
    
- name: Get information about all clusters
  cloudera.cluster.cm_cluster_info:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: "7180"

"""

RETURN = r"""
---
clusters:
    description: Details about Cloudera Manager Cluster
    type: list
    elements: dict
    contains:
        cluster_type:
            description: The type of Cloudera Manager cluster.
            type: str
            returned: always
        cluster_url:
            description: Url of Cloudera Manager cluster.
            type: str
            returned: always
        display_name:
            description: The name of the cluster displayed on the site.
            type: str
            returned: always
        entity_status:
            description: Health status of the cluster.
            type: str
            returned: always
        full_version:
            description: Version of the cluster installed.
            type: str
            returned: always
        hosts_url:
            description: Url of all the hosts on which cluster is installed.
            type: str
            returned: always
        maintenance_mode:
            description: Maintance mode of Cloudera Manager Cluster.
            type: bool
            returned: always
        maintenance_owners:
            description: List of Maintance owners for Cloudera Manager Cluster.
            type: list
            returned: always
        name:
            description: The name of the cluster.
            type: str
            returned: always
        tags:
            description: List of tags for Cloudera Manager Cluster.
            type: list
            returned: always
        uuid:
            description: Unique ID of the cluster
            type: bool
            returned: always
"""


class ClusterInfo(ClouderaManagerModule):
    def __init__(self, module):
        super(ClusterInfo, self).__init__(module)
        self.name = self.get_param("name")
        self.output = []
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        try:
            cluster_api_instance = ClustersResourceApi(self.api_client)
            if self.name:
                self.output = [cluster_api_instance.read_cluster(cluster_name=self.name).to_dict()]
            else:
                self.output = cluster_api_instance.read_clusters().to_dict()['items']
                
        except ApiException as e:
            if e.status == 404:
                pass
            else:
                raise e
        except KeyError as ke:
            self.module.fail_json(msg='Invalid result object from Cloudera Manager API', error=to_native(ke))


def main():
    module = ClouderaManagerModule.ansible_module(
        
        argument_spec=dict(
            name=dict(aliases=["cluster_name","cluster"]),
        ),
          supports_check_mode=True
          )

    result = ClusterInfo(module) 
    
    output = dict(
        changed=False,
        clusters=result.output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
