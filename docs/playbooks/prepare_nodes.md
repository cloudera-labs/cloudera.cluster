# Playbook: Prepare nodes

Install required software packages and apply pre-requisite operating system configurations.

## Required inventory groups
- `cloudera_manager`
- `cluster`

## Plays

### Apply OS pre-requisite configurations

Applies role [`prereqs/os`](/docs/roles/prereqs/os.md) to hosts in group `cloudera_manager` and `cluster`

### Install JDK

Applies role [`prereqs/jdk`](/docs/roles/prereqs/jdk.md) to hosts in group `cloudera_manager` and `cluster`

### Download MySQL Connector

Runs role [`prereqs/mysql_connector/download`](/docs/roles/prereqs/mysql_connector/download.md) locally, only when the following condition is met: `database_type == 'mysql' or database_type == 'mariadb'`

### Install MySQL Connector

Applies role [`prereqs/mysql_connector/install`](/docs/roles/prereqs/mysql_connector/install.md) to hosts in group `cloudera_manager` and `cluster`, only when the following condition is met: `database_type == 'mysql' or database_type == 'mariadb'`

