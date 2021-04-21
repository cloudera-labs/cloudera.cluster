#!/usr/bin/python
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


class FilterModule(object):

  def filters(self):
    return {
      'filter_null_configs': self.filter_null_configs
    }

  def filter_null_configs(self, configs, existing_configs):
    filtered_configs = dict(configs)
    for item, value in configs.items():
      if item not in existing_configs and not value:
        del filtered_configs[item]
    return filtered_configs
