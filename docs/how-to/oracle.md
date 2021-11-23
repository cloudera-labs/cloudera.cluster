# How to: Oracle

The guide will run through specifics for deploying clusters using Oracle.

It assumes you are already familiar with deploying standard clusters using these playbooks.

1. Create the databases and users

As the Oracle database is external to the playbook, this step is not completed automatically.

Here, it is important you ensure that each service has the required permissions and that each node can access the database.

2. Ensure the JDBC driver is available

The playbook will install the JDBC driver via maven.

By default, the playbook will search for the public maven repository, however, this can be overridden by setting `maven_repo` in `extra_vars.yml` to your maven repository.

3. Ensure the instant client is available

The playbook will install the instant client using zip files local to the Ansible controller.

Please upload the instant client basic and sdk zip to the Ansible controller and set `oracle_instantclient_basic_zip` and `oracle_instantclient_sdk_zip` to these locations.

4. Configure `extra_vars.yml` with the connection information

Here, you'll want to set:

- `database_type` to `oracle`
- `database_host` to the Oracle host
- `database_name` to the Oracle database name (optional but helps below)
- `cloudera_manager_database_name` to the appropriate database
- `cloudera_manager_database_user` to the appropriate user
- `cloudera_manager_database_password` to the appropriate password

5. Configure `cluster.yml` with the service database information

This step is a bit more involved and is mostly identical to the steps required for configuring any other external database.

Here, you'll want to add a `databases` dictionary to each cluster and the mgmt cluster (at the same level as `name`).

This dictionary contains an entry for each service with a database in the cluster:

e.g. For Hive:

```
HIVE:
  host: "{{ database_host }}"
  port: "{{ database_type | default_database_port }}"
  type: "{{ database_type }}"
  name: "{{ database_name }}"
  user: hive
  password: "{{ vault__database_hive }}"
```

E.g. Complete example:

```
---
clusters:
  - name: Cluster
    services: [HDFS, HIVE, HIVE_ON_TEZ, OOZIE, TEZ, QUEUEMANAGER, YARN, ZOOKEEPER]
    repositories:
      - https://archive.cloudera.com/p/cdh7/7.1.4.2/parcels/
    databases:
      HIVE:
        host: "{{ database_host }}"
        port: "{{ database_type | default_database_port }}"
        type: "{{ database_type }}"
        name: "{{ database_name }}"
        user: hive
        password: "{{ database_default_password }}"
      OOZIE:
        host: "{{ database_host }}"
        port: "{{ database_type | default_database_port }}"
        type: "{{ database_type }}"
        name: "{{ database_name }}"
        user: oozie
        password: "{{ database_default_password }}"
    configs:
      ZOOKEEPER:
        SERVICEWIDE:
          zookeeper_datadir_autocreate: true
    host_templates:
      Master1:
        HDFS: [NAMENODE, SECONDARYNAMENODE, HTTPFS]
        HIVE: [HIVEMETASTORE, GATEWAY]
        HIVE_ON_TEZ: [HIVESERVER2]
        OOZIE: [OOZIE_SERVER]
        QUEUEMANAGER: [QUEUEMANAGER_STORE, QUEUEMANAGER_WEBAPP]
        TEZ: [GATEWAY]
        YARN: [RESOURCEMANAGER, JOBHISTORY]
        ZOOKEEPER: [SERVER]
      Workers:
        HDFS: [DATANODE]
        HIVE: [GATEWAY]
        HIVE_ON_TEZ: [GATEWAY]
        TEZ: [GATEWAY]
        YARN: [NODEMANAGER]

mgmt:
  name: Cloudera Management Service
  services: [ALERTPUBLISHER, EVENTSERVER, HOSTMONITOR, REPORTSMANAGER, SERVICEMONITOR]
  databases:
    REPORTSMANAGER:
      host: "{{ database_host }}"
      port: "{{ database_type | default_database_port }}"
      type: "{{ database_type }}"
      name: "{{ database_name }}"
      user: rman
      password: "{{ database_default_password }}"

hosts:
  configs:
    host_default_proc_memswap_thresholds:
      warning: never
      critical: never
    host_memswap_thresholds:
      warning: never
      critical: never
    host_config_suppression_agent_system_user_group_validator: true
```

Examples of cluster services requiring a database include:

- DAS
- HIVE
- HUE
- OOZIE
- RANGER
- SCHEMAREGISTRY
- STREAMS_MESSAGING_MANAGER
- SENTRY

Examples of CMS services requiring a database include:

- ACTIVITYMONITOR
- NAVIGATOR
- NAVIGATORMETASERVER
- REPORTSMANAGER

6. Deploy as usual

Provided the steps above have been completed successfully, everything else should follow normally.

7. Configure an oracle client for tablespace teardown (optional)

Optionally, the playbook can be configured to delete each Oracle user's tablespace on teardown.

Please first ensure you have access (via SSH) to a host that is able to access the Oracle database using the `sqlplus` client.

Then, in `extra_vars.yml`, configure the following:

- `teardown_oracle_preamb` (shell commands required to setup environment)
- `teardown_oracle_client_host` (hostname of database client)
- `teardown_oracle_user` (local user to become)

E.g.

```
teardown_oracle_preamb: |
  export ORACLE_HOME=/opt/oracle/product/19c/dbhome_1
  export PATH=${PATH}:${ORACLE_HOME}/bin
  export ORACLE_SID=ORCLPDB2
teardown_oracle_client_host: db-client-1.example.com
teardown_oracle_user: oracle
```

With these configs in place, teardown will clean up the tablespaces.
