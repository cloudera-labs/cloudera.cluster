# How to: Database Configuration

This guide will run through the specifics of explicitly configuring databases for Cloudera Manager and the cluster services.

It assumes you are already familiar with deploying standard clusters using these playbooks.

### Create a cluster definition

Create the cluster definition you wish to deploy.

### Configure the Cloudera Manager database

Add the following variables to `extra_vars.yml`:

- `cloudera_manager_database_host`
- `cloudera_manager_database_name`
- `cloudera_manager_database_user`
- `cloudera_manager_database_password`

You can also set the following variable if the Cloudera Manager database type is different from the global `database_type` setting:

- `cloudera_manager_database_type`

### Configure the cluster service databases

**Note:** The type of every service database is expected match `database_type` (default postgres).

For each cluster in the cluster list, add a dictionary entry `databases:`, level with `configs:`.

Add an entry to the `databases:` dictionary for each service that requires a database. The service label should match the label in `services:` and `configs:`.

For each service, set the following variables:

- `name` (name of the database)
- `host`
- `user`
- `password`

Following these changes, your clusters should look like:

```
clusters:
  - name: Test Cluster
    services: [HDFS, ...]
    databases:
      HIVE:
        name: "metastore"
        host: "db-1.example.com"
        user: "hive"
        password: "{{ hive_password }}"
      ...
    ...
  ...
```

### Configure the mgmt databases

**Note:** The type of every mgmt role database is expected match `database_type` (default postgres).

To config mgmt databases, following the method explained above for clusters, placing `databases:` in `mgmt:`.

Following these changes, mgmt should look like:

```
mgmt:
  name: Cloudera Management Service
  services: [REPORTSMANAGER, ...]
  databases:
    REPORTSMANAGER:
      name: "rman"
      host: "db-2.example.com"
      user: "rman"
      password: "{{ rman_password }}"
    ...
  ...
```

### **Deploy!**

**Note:** If the configured database host is provisioned by the playbook (part of the `db_servers` host group) the database will be created automatically.
