# cm_agent

Install Cloudera Manager agent packages.

This role installs the Cloudera Manager agent packages on a target host and configures it to connect to a specified Cloudera Manager server. The management of the agent's version is handled implicitly through the configured package repository profile, ensuring compatibility with the Cloudera Manager server.

The role will:
- Install the necessary Cloudera Manager agent packages.
- Configure the agent to point to the `cloudera_manager_host`.
- Enable and start the Cloudera Manager agent service.

# Requirements

- A valid Java JDK is required on the target host.
- A valid Cloudera Manager package repository must be configured and accessible on the target host.

# Dependencies

None.

# Parameters

| Variable | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `cloudera_manager_host` | `str` | `True` | | Hostname of the Cloudera Manager server (e.g., `cm.example.com`). |

# Example Playbook

```yaml
- hosts: cm_agents
  tasks:
    - name: Install Cloudera Manager agent on hosts
      ansible.builtin.import_role:
        name: cm_agent
      vars:
        cloudera_manager_host: cm.mycluster.internal
```

# License

```
Copyright 2025 Cloudera, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
