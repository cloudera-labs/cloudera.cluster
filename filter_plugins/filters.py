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
        'flatten_dict_list': self.flatten_dict_list
    }

  def flatten_dict_list(self, item, level=2, sep='_', show_index=False):
    ''' flatten a structure of dicts and lists into a flat array

        e.g. { "a": [1, 2, 3], "b": { "c": "d", "e": "f" } }
             with level=2
             becomes ["a_1", "a_2", "a_3", "b_c", "b_d"]
    '''

    state = []

    def _flatten_dict_list(i, l, parents):
      if l > 0:
        if isinstance(i, dict):
          for key, value in i.items():
            _flatten_dict_list(value, l-1, parents + [str(key)])
  
        elif isinstance(i, list):
          for index, value in enumerate(i):
            if show_index:
              _flatten_dict_list(value, l, parents + [str(index)])
            else:
              _flatten_dict_list(value, l, parents)
  
        else:
          state.append(sep.join(parents + [str(i)]))

      if l == 0 and len(parents) > 0:
        state.append(sep.join(parents))

    _flatten_dict_list(item, level, [])

    return state
