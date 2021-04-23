# Copyright 2021 Cloudera, Inc.
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

from ansible.plugins.action import ActionBase
from ansible.errors import AnsibleError
from ansible.utils.display import Display

import time

display = Display()

class ActionModule(ActionBase):

  def build_url(self, api_base, api_endpoint):
    if not api_endpoint.startswith("/"):
      api_endpoint = "/" + api_endpoint
    return api_base + api_endpoint

  def build_args(self, task_vars, additional_args=dict()):
    args = dict(
      body_format = "json",
      force_basic_auth=True,
      url_username=task_vars['cloudera_manager_api_user'],
      url_password=task_vars['cloudera_manager_api_password'],
      return_content=True,
      validate_certs=task_vars['cloudera_manager_tls_validate_certs']
    )
    args.update(additional_args)
    return args

  def get_api_base_url(self, task_vars):
    # If there's already a value in task vars, just use that
    if 'cloudera_manager_api' in task_vars:
      api_base = task_vars['cloudera_manager_api']
      result = None
    else:
      # Call /api/version endpoint to find the correct API version number.
      url = self.build_url(task_vars['cloudera_manager_url'], '/api/version')
      args = self.build_args(task_vars, dict(url=url))
      result = self._execute_module('uri', module_args=args, task_vars=task_vars, wrap_async=self._task.async_val)
      # We use the URL returned in the result rather than the one we defined originally.
      # This has the benefit of allowing to use TLS-enabled endpoints later if the call was redirected.
      api_base = result["url"].replace("version", result['content']) if result['status'] == 200 else None
    return (api_base, result)

  def poll_command_status(self, task_vars, api_base_url, command_id):
    args = self.build_args(task_vars, additional_args=dict(
      url = self.build_url(api_base_url, "/commands/" + str(command_id))
    ))
    result = self._execute_module('uri', module_args=args, task_vars=task_vars, wrap_async=self._task.async_val)
    return result

  def run(self, tmp=None, task_vars=None):

    result = super(ActionModule, self).run(tmp, task_vars)

    # Get Cloudera Manager API base url from task vars, or work it out ourselves
    api_base_url, api_base_result = self.get_api_base_url(task_vars)
    if not api_base_url:
      result.update(api_base_result)
      return result

    # Add endpoint and request method to base args containing creds etc
    uri_module_args = self.build_args(task_vars, additional_args=dict(
      url = self.build_url(api_base_url, self._task.args['endpoint']),
      method = self._task.args.get('method') or 'GET',
      status_code = self._task.args.get('status_code') or '200',
      timeout = self._task.args.get('timeout') or '30'
    ))

    poll_duration = int(self._task.args.get('poll_duration') or 10)
    poll_max_failed_retries = int(self._task.args.get('poll_max_failed_retries') or 3)

    # Add request body if necessary
    if 'body' in self._task.args:
      uri_module_args.update(body = self._task.args['body'])

    # Send request to CM API
    uri_result = self._execute_module('uri', module_args=uri_module_args, task_vars=task_vars, wrap_async=self._task.async_val)
    result.update(uri_result)

    # If we get ApiCommand response, and it is active, wait for completion
    failed_polls = 0
    if 'json' in uri_result:
      response = uri_result['json']
      if 'id' in response and 'active' in response:
        command_id = response['id']
        command_name = response['name']
        command_active = response['active']
        while command_active and failed_polls < poll_max_failed_retries:
          time.sleep(poll_duration)
          display.vv("Waiting for {} command ({}) to complete...".format(command_name, command_id))
          command_status = self.poll_command_status(task_vars, api_base_url, command_id)
          if 'json' in command_status:
            failed_polls = 0
            response = command_status['json']
            command_active = response['active']
          else:
            failed_polls += 1
            response = {'success': False}
            display.vv("Failed to poll command ({}) for status (attempt {} of {})...".format(
                command_id, failed_polls, poll_max_failed_retries))
          result.update(command_status)
        result['failed'] = not response['success']

    return result
