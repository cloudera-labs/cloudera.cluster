# Playbook: Install Cloudera Manager

Install Cloudera Manager Server and agents, configure its database and apply license if available.

## Required inventory groups
- `cluster`
- `cloudera_manager`

## Plays

### Install Cloudera Manager server

Applies role [`cloudera_manager/server`](/docs/roles/cloudera_manager/server.md) to hosts in group `cloudera_manager`

### Install Cloudera Manager agents

Applies role [`cloudera_manager/agent`](/docs/roles/cloudera_manager/agent.md) to hosts in group `cloudera_manager`, `cluster`

### Apply Cloudera Manager license

Runs role [`cloudera_manager/license`](/docs/roles/cloudera_manager/license.md) locally

### Configure Cloudera Manager server

Runs role [`cloudera_manager/config`](/docs/roles/cloudera_manager/config.md) locally
