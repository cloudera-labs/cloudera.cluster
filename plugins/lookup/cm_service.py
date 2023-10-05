# Copyright 2023 Cloudera, Inc.
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

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
    lookup: cm_service
    author: Webster Mudge (@wmudge) <wmudge@cloudera.com>
    short_description: Get the details for a service on a CDP Datahub cluster
    description:
        - Allows you to retrieve the name or full details for a given service on a CDP Datahub cluster.
        - If no service name is found on the specified cluster, the lookup returns the value of I(default).
        - Otherwise, the lookup entry will be an empty list.
        - If the cluster is not found or is ambigious, the lookup will return an error.
        - If the Cloudera Manager endpoint is not found or is not available, the lookup will return an error.
    options:
        _terms:
            description:
                - A C(service) or list of services to lookup within the CDP Datahub cluster.
            required: True
        cluster:
            description: Name of the Datahub cluster to query.
            type: string
            required: True
        detailed:
            description: Whether to return the full details of the service or just the name.
            type: boolean
            default: False
        username:
            description: Username for accessing the Cloudera Manager API.
            type: string
            required: True
            env:
                - name: CM_USERNAME
        password:
            description: Password for accessing the Cloudera Manager API.
            type: string
            required: True
            env:
                - name: CM_PASSWORD
        endpoint:
            description: API endpoint of Cloudera Manager.
            type: string
            required: False
        force_tls:
            description:
                - Whether to force the HTTPS scheme when discovering the Cloudera Manager API endpoint.
                - Ignored if C(endpoint) is defined.
            type: boolean
            default: True
        host:
            description:
                - Hostname when discovering the Cloudera Manager API endpoint.
                - Ignored if C(endpoint) is defined.
            type: string
        port:
            description:
                - Port when discovering the Cloudera Manager API endpoint.
                - Ignored if C(endpoint) is defined.
            type: integer
            default: 7183
        verify_tls:
            description: Whether to verify the TLS credentials of the Cloudera Manager API endpoint.
            type: boolean
            default: True
        debug:
            description: Whether to log the I(urllib) connection details.
            type: boolean
            default: False
        default:
            description: Value to return if no service is found on the cluster.
            type: any
        version:
            description: Version number of the Cloudera Manager API.
            type: string
            default: v40
        agent_header:
            description: Header string to identify the connection.
            type: string
            default: cm_service     
    notes:
        - Requires C(cm_client).
'''

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_controller_utils import ClouderaManagerLookupBase


class LookupModule(ClouderaManagerLookupBase):
    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        
        self.initialize_client()
        all_services = {service['type']:service for service in self.get("%s/clusters/%s/services" % (self.get_option('version'), self.get_option('cluster')))}
        
        results = []
        for term in LookupModule._flatten(terms):
            if term in all_services:
                results.append(all_services[term] if self.get_option('detailed') else all_services[term]['name'])
            else:
                if self.get_option('default') is not None:
                    results.append(self.get_option('default'))
                elif self.get_option('detailed'):
                    results.append({})
                else:
                    results.append("")
        return results
