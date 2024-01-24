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
from cm_client import MgmtRolesResourceApi
from cm_client import MgmtServiceResourceApi
from cm_client import MgmtRoleCommandsResourceApi
from cm_client import HostsResourceApi

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: cm_service
short_description: Manage Cloudera Manager service roles  
description:
  - Create or remove one or more Cloudera Manager service roles.
  - Start, stop or restart one or more Cloudera Manager service roles.
author:
  - "Ronald Suplina (@rsuplina)"
options:
  role:
    description:
      - A list of one or more service roles to be configured.
    type: list
    elements: str
    required: True
  purge:
    description:
      - Delete all current roles and setup only the roles provided
    type: bool
    required: False
    default: False
  state:
    description:
      - The desired state of roles
    type: str
    default: 'started'
    choices:
      - 'started'
      - 'stopped'
      - 'absent'
      - 'present'
      - 'restarted'
    required: False

requirements:
  - cm_client
"""

EXAMPLES = r"""
---
- name: Start Cloudera Manager service roles
  cloudera.cluster.cm_version:
    host: "10.10.10.10"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: "7180"
    purge: False
    state: "started"
    role: [ "SERVICEMONITOR" , "HOSTMONITOR", "EVENTSERVER", "ALERTPUBLISHER" ]
  register: cm_output

- name: Purge all roles then create and start new roles 
  cloudera.cluster.cm_version:
    host: "10.10.10.10"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: "7180"
    purge: True
    state: "started"
    role: [ "SERVICEMONITOR" , "HOSTMONITOR", "EVENTSERVER", "ALERTPUBLISHER" ]
  register: cm_output

- name: Stop two Cloudera Manager service  roles
  cloudera.cluster.cm_version:
    host: "10.10.10.10"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: "7180"
    state: "stopped"
    role: [ "EVENTSERVER", "ALERTPUBLISHER" ]
  register: cm_output
 
- name: Remove Cloudera Manager service role
  cloudera.cluster.cm_version:
    host: "10.10.10.10"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: "7180"
    purge: False
    state: "absent"
    role: [ "ALERTPUBLISHER" ]
  register: cm_output
"""

RETURN = r"""
---
cloudera_manager:
    description: List of Cloudera Manager roles
    type: dict
    contains:
        name:
            description: The Cloudera Manager role name.
            type: str
            returned: optional
        type:
            description: The Cloudera Manager role type.
            type: str
            returned: optional
        serviceRef:
            description: Reference to a service.
            type: str
            returned: optional
        service_url:
            description: Role url for Cloudera Manager Role.
            type: str
            returned: optional
        hostRef:
            description: Reference to a host.
            type: str
            returned: optional
        role_state:
            description: State of the Cloudera Manager Role.
            type: str
            returned: optional
        commissionState:
            description: Commission state of the role.
            type: str
            returned: optional
        health_summary:
            description: Health of the Cloudera Manager Role.
            type: str
            returned: optional
        roleConfigGroupRef:
            description: Reference to role config groups.
            type: str
            returned: optional
        configStalenessStatus:
            description: Status of configuration staleness for Cloudera Manager Role.
            type: str
            returned: optional
        health_checks:
            description: Lists all available health checks for Cloudera Manager Service.
            type: dict
            returned: optional
        role_instances_url:
            description: Role instance url for Cloudera Manager Service.
            type: str
            returned: optional
        maintenance_mode:
            description: Maintance mode of Cloudera Manager Role.
            type: bool
            returned: optional
        maintenance_owners:
            description: List of Maintance owners for Cloudera Manager Service.
            type: list
            returned: optional
        entity_status:
            description: Health status of entities for Cloudera Manager Role.
            type: str
            returned: optional
        tags:
            description: List of tags for Cloudera Manager Role.
            type: list
            returned: optional
"""


class ClouderaService(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaService, self).__init__(module)

        self.role = self.get_param("role")
        self.state = self.get_param("state")
        self.purge = self.get_param("purge")
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        try:
            api_instance = MgmtServiceResourceApi(self.api_client)
            role_api_instance = MgmtRolesResourceApi(self.api_client)
            role_cmd_api_instance = MgmtRoleCommandsResourceApi(self.api_client)
            mgmt_service_api_instance = MgmtServiceResourceApi(self.api_client)
            host_api_instance = HostsResourceApi(self.api_client)

            get_host_infomation = host_api_instance.read_hosts().to_dict()
            for item in get_host_infomation['items']:
              if self.host == item['hostname']:
                host_id = item['host_id']

            if not self.purge:
              available_roles_info = role_api_instance.read_roles().to_dict()
              existing_roles = []
              for item in available_roles_info['items']:
                existing_roles.append(item['type'])


              if self.state in ['present']:
                not_existing_roles = []
                for role in self.role:
                    if role not in existing_roles:
                      not_existing_roles.append(role)
                if not_existing_roles:
                  body = {"items": [{ "type": role, "hostRef" : { "hostId" : host_id }} for role in not_existing_roles]}
                  role_api_instance.create_roles(body=body)
                self.cm_service_output = role_api_instance.read_roles().to_dict()
                self.changed = True


              elif self.state in ['absent']:
                roles_to_remove = [role for role in self.role if role in existing_roles]
                roles_to_remove_extended_info = []
                for role in roles_to_remove:
                    for item in available_roles_info['items']:
                      if role == item['type']:
                          roles_to_remove_extended_info.append(item['name'])
                if not roles_to_remove_extended_info:
                    self.cm_service_output = role_api_instance.read_roles().to_dict()
                    self.changed = False
                else:
                    for role in roles_to_remove_extended_info:
                        role_api_instance.delete_role(role_name=role)
                    self.cm_service_output = role_api_instance.read_roles().to_dict()
                    self.changed = True

                
              elif self.state in ['started']:
 
                matching_roles = []
                new_roles = []
                for role in self.role:
                  if role in existing_roles:
                    matching_roles.append(role)
                  else:
                    new_roles.append(role)
                    
                new_roles_to_start = []
                if new_roles:
                    body = {"items": [{"type": role, "hostRef": {"hostId": host_id}} for role in new_roles]}
                    newly_added_roles=role_api_instance.create_roles(body=body).to_dict()

                    for role in newly_added_roles['items']:
                      new_roles_to_start.append(role['name'])
                    body = { "items" : new_roles_to_start}

                existing_roles_state = []
                for role in matching_roles:
                    for item in available_roles_info['items']:
                        if role == item['type']:
                          existing_roles_state.append({'type': item['type'], 'role_state': item['role_state'].lower(),'name': item['name'] })
   
                existing_roles_to_start = []
                for role in existing_roles_state:
                  if role['role_state'] == 'stopped':
                    existing_roles_to_start.append(role['name'])

                all_roles_to_start = new_roles_to_start + existing_roles_to_start
                body = { "items" : all_roles_to_start}

                if all_roles_to_start:
                  start_roles_request = role_cmd_api_instance.start_command(body=body).to_dict()
                  command_id = start_roles_request['items'][0]['id']
                  self.wait_for_command_state(command_id=command_id,polling_interval=5)
                  self.cm_service_output = role_api_instance.read_roles().to_dict()
                  self.changed = True
                else:
                  self.cm_service_output = role_api_instance.read_roles().to_dict()
                  self.changed = False     


              elif self.state in ['stopped']:
                matching_roles = []
                for role in self.role:
                  if role in existing_roles:
                    matching_roles.append(role)

                matching_roles_state = []
                for role in matching_roles:
                    for item in available_roles_info['items']:
                        if role == item['type']:
                          matching_roles_state.append({'type': item['type'], 'role_state': item['role_state'].lower(),'name': item['name'] })

                roles_to_stop = []
                for role in matching_roles_state:
                  if role['role_state'] == 'started':
                    roles_to_stop.append(role['name'])
                body = { "items" : roles_to_stop }

                if roles_to_stop:
                  role_cmd_api_instance.stop_command(body=body)
                  self.cm_service_output = role_api_instance.read_roles().to_dict()
                  self.changed = True
                else:
                  self.cm_service_output = role_api_instance.read_roles().to_dict()
                  self.changed = False

              elif self.state in ['restarted']:
                matching_roles = []
                for role in self.role:
                  if role in existing_roles:
                    matching_roles.append(role)

                matching_roles_state = []
                for role in matching_roles:
                    for item in available_roles_info['items']:
                        if role == item['type']:
                          matching_roles_state.append({'type': item['type'], 'role_state': item['role_state'].lower(),'name': item['name'] })

                roles_to_restart = []
                for role in matching_roles_state:
                  roles_to_restart.append(role['name'])
                body = { "items" : roles_to_restart}
                
                if roles_to_restart:
                  role_cmd_api_instance.restart_command(body=body)
                  self.cm_service_output = role_api_instance.read_roles().to_dict()
                  self.changed = True

                
            if self.purge:
              mgmt_service_api_instance.delete_cms()
              body = {"roles": [{"type": role} for role in self.role]}
              mgmt_service_api_instance.setup_cms(body=body)
              self.cm_service_output = role_api_instance.read_roles().to_dict()

              if self.state in ['started']:
                    start_roles_request=api_instance.start_command().to_dict()
                    command_id = start_roles_request['id']
                    self.wait_for_command_state(command_id=command_id,polling_interval=5)
                    self.cm_service_output = role_api_instance.read_roles().to_dict()
              self.changed = True
               
                
        except ApiException as e:
            if e.status == 404 or 400:
                roles_dict = {"roles": [{"type": role} for role in self.role]}
                api_instance.setup_cms(body=roles_dict)

                if self.state in ['started']:
                    start_roles_request=api_instance.start_command().to_dict()
                    command_id = start_roles_request['id']
                    self.wait_for_command_state(command_id=command_id,polling_interval=5)
                    self.cm_service_output = role_api_instance.read_roles().to_dict()
                else:
                  self.cm_service_output = role_api_instance.read_roles().to_dict()
                self.changed = True

def main():
    module = ClouderaManagerModule.ansible_module(
        
        argument_spec=dict(
            role=dict(required=True, type="list"),
            purge=dict(required=False, type="bool", default=False),
            state=dict(type='str', default='started', choices=['started', 'stopped','absent','present','restarted']),
                          ),
          
          supports_check_mode=False
          )

    result = ClouderaService(module)
 
    changed = result.changed

    output = dict(
        changed=changed,
        cloudera_manager=result.cm_service_output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
