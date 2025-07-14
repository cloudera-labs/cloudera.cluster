# cm_server

Install Cloudera Manager server.

This role automates the installation of Cloudera Manager server packages, configures its command-line arguments and Java options, and prepares its database connection. It supports both embedded and external database configurations. When using an external database, the database server and its respective Java client libraries must be pre-installed and configured on the Cloudera Manager server host. Version management for the Cloudera Manager server is handled implicitly via the configured package repository profile.

The role will:
- Install the specified Cloudera Manager server packages.
- Configure command-line arguments for the Cloudera Manager server process.
- Set Java Virtual Machine (JVM) options for the Cloudera Manager server.
- Configure the database connection parameters for the Cloudera Manager server's metadata.
- Optionally, install packages for and prepare the Cloudera Manager server's embedded database if selected.
- Prepare the Cloudera Manager server database (schema creation, etc.).

# Requirements

- A valid Java Development Kit (JDK) must be installed on the target host.
- A valid Cloudera Manager package repository must be configured and accessible on the target host.
- **For external databases:** The external database server (PostgreSQL, Oracle, or MySQL) must be installed, configured, and accessible from the Cloudera Manager server host. Additionally, the corresponding JDBC driver (Java client libraries) must be installed on the Cloudera Manager server host prior to running this role.
- **For embedded database:** PostgreSQL 10 is required and is *not* installed by this role; the `cloudera-manager-server-db-2` package pulls it as a dependency.

# Dependencies

None.

# Parameters

| Variable | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `cloudera_manager_server_packages` | `list` of `str` | `False` | `["cloudera-manager-server"]` | List of packages to install for the Cloudera Manager server. |
| `cloudera_manager_cmf_server_args` | `str` | `False` | | Cloudera Manager server command line arguments (e.g., for custom flags). |
| `cloudera_manager_cmf_java_opts` | `str` | `False` | `-Xmx4G -XX:MaxPermSize=256m -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/tmp` | Cloudera Manager server Java options for JVM tuning. |
| `cloudera_manager_server_embedded_db_packages` | `list` of `str` | `False` | `["cloudera-manager-server-db-2"]` | List of packages to install specifically for the Cloudera Manager server embedded database. Only relevant if `cloudera_manager_database_type` is `embedded`. |
| `cloudera_manager_database_type` | `str` | `False` | `postgresql` | Database type for the Cloudera Manager server. If not `embedded`, the external database must be configured prior to running this role. Valid choices are `postgresql`, `oracle`, `mysql`, `embedded`. |
| `cloudera_manager_database_host` | `str` | `True` if `cloudera_manager_database_type != embedded` | | Database hostname for the Cloudera Manager server. |
| `cloudera_manager_database_port` | `int` | `True` if `cloudera_manager_database_type != embedded` | | Database port for the Cloudera Manager server. |
| `cloudera_manager_database_name` | `str` | `False` | `scm` | Database name for the Cloudera Manager server. |
| `cloudera_manager_database_user` | `str` | `False` | `scm` | Database username for the Cloudera Manager server. |
| `cloudera_manager_database_password` | `str` | `True` if `cloudera_manager_database_type != embedded` | | Database password for the Cloudera Manager server. |

# Example Playbook

```yaml
- hosts: cm_server_host
  tasks:
    - name: Install Cloudera Manager server with embedded database
      ansible.builtin.import_role:
        name: cloudera.cluster.cm_server
      vars:
        cloudera_manager_database_type: embedded
        # The 'cloudera_manager_server_embedded_db_packages' default will be used.
        # No database connection details (host, port, user, password) are needed for embedded.

    - name: Install Cloudera Manager server with external PostgreSQL database
      ansible.builtin.import_role:
        name: cloudera.cluster.cm_server
      vars:
        cloudera_manager_database_type: postgresql
        cloudera_manager_database_host: "db.example.com"
        cloudera_manager_database_port: 5432
        cloudera_manager_database_name: "scm_prod"
        cloudera_manager_database_user: "scm_user"
        cloudera_manager_database_password: "super_secure_password"
        cloudera_manager_cmf_java_opts: "-Xmx8G -XX:+UseG1GC" # Custom Java opts
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
