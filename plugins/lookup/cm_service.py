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
    lookup: datalake_service
    author: Webster Mudge (@wmudge) <wmudge@cloudera.com>
    short_description: Get the URL for a CDP Public Cloud Datalake service
    description:
        - Allows you to retrieve the URL for a given CDP Public Cloud Datalake service.
        - If no service name (or optionally Knox service name) is found on the specified Datalake, the lookup returns the value of I(default).
        - Otherwise, the lookup entry will be an empty list.
        - If the Datalake is not found or is ambigious, the lookup will return an error.
    options:
        _terms:
            description:
                - An endpoint C(serviceName) or list of them to lookup within the Datalake.
                - If I(knox_service=True), then these values will lookup against the endpoint C(knoxService).
            required: True
            sample:
                - CM-API
                - CM-UI
                - ATLAS_SERVER
                - RANGER_ADMIN
        endpoint:
            description: API endpoint of Cloudera Manager
            type: string
            required: True
        cluster:
            description: Name of the Datahub Cluster to query
            type: string
            required: True
        detailed:
            type: boolean
            default: False
        username:
            type: string
            required: True
        password:
            type: string
            required: True
            no_log: True
        force_tls:
            type: boolean
            default: True
        host:
            type: string
        port:
            type: integer
        verify_tls:
            type: boolean
            default: False
        debug:
            type: boolean
            default: False
        default:
            type: any
        agent_header:
            type: string
            default: cm_service     
    notes:
        - Requires C(cm_client).
'''

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.cloudera.cluster.plugins.lookup.cm_api import ClouderaManagerLookupBase

from ansible.utils.display import Display

from pprint import pp
display = Display()

class LookupModule(ClouderaManagerLookupBase):
    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        
        self.initialize_client()
        all_services = {service['type']:service for service in self.get("v40/clusters/%s/services" % self.get_option('cluster'))}
        
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
