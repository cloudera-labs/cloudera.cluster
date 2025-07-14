# cm_csds

Download CSDs.

This role downloads a specified list of Cloudera Custom Services Descriptor (CSD) files to a designated directory, typically on a Cloudera Manager Server host. It can optionally trigger a restart of the Cloudera Manager Server to apply the newly downloaded CSDs and supports authentication for downloading CSDs from protected repositories.

The role will:
- Ensure the `cloudera_manager_csd_directory` exists and has appropriate permissions.
- Download each CSD file specified in `cloudera_manager_csds` to the CSD directory.
- If `cloudera_manager_csd_restarted` is true, restart the Cloudera Manager Server service.
- Handle authentication for CSD downloads if `cloudera_manager_repo_username` and `cloudera_manager_repo_password` are provided.

# Requirements

- Network access from the target host to the URLs specified in `cloudera_manager_csds`.
- Write permissions for the Ansible user on the `cloudera_manager_csd_directory`.
- If `cloudera_manager_csd_restarted` is set to `true`, the target host must be the Cloudera Manager Server, and the Ansible user must have permissions to restart its service.

# Dependencies

None.

# Parameters

| Variable | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `cloudera_manager_csd_directory` | `str` | `False` | `/opt/cloudera/csd` | Location where CSD JAR files are downloaded on the target host. |
| `cloudera_manager_csds` | `list` of `str` | `False` | `[]` | A list of URLs pointing to the CSD JAR files to download. |
| `cloudera_manager_csd_restarted` | `bool` | `False` | `false` | Flag to restart the Cloudera Manager Server service after downloading CSDs. Set to `true` to apply new CSDs immediately. |
| `cloudera_manager_repo_username` | `str` | `False` | | Username for authenticating to a protected Cloudera package repository from which CSDs might be downloaded. |
| `cloudera_manager_repo_password` | `str` | `False` | | Password for authenticating to a protected Cloudera package repository from which CSDs might be downloaded. |

# Example Playbook

```yaml
- hosts: cm_server
  tasks:
    - name: Download specified CSDs and restart CM
      ansible.builtin.import_role:
        name: cloudera.cluster.cm_csds
      vars:
        cloudera_manager_csds:
          - "https://archive.cloudera.com/csd/service_name-1.0.jar"
          - "https://my-internal-repo.example.com/custom_service-2.0.jar"
        cloudera_manager_csd_restarted: true
        cloudera_manager_repo_username: "my_repo_user" # Only if CSDs are in a protected repo
        cloudera_manager_repo_password: "my_repo_password" # Only if CSDs are in a protected repo

    - name: Download CSDs to a custom directory without restarting
      ansible.builtin.import_role:
        name: cloudera.cluster.cm_csds
      vars:
        cloudera_manager_csd_directory: "/usr/local/cloudera/csd_extra"
        cloudera_manager_csds:
          - http://another.example.com/another_csd.jar"
        cloudera_manager_csd_restarted: false
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
