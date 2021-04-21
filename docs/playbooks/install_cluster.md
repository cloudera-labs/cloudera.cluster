# Playbook: TODO

TODO - Description

## Required inventory groups

None

## Plays

### Deploy Cloudera Management Service

Runs role [`deployment/mgmt_service`](/docs/roles/deployment/mgmt_service.md) locally. 

Creates databases and users for Cloudera Management Services if required. 
Generates a service template for Cloudera Management Services and posts to Cloudera Manager API.

### Deploy clusters

Runs role [`deployment/cluster`](/docs/roles/deployment/cluster.md) locally.

Generates one or more cluster template and posts to Cloudera Manager API.