# Playbook: Create Infrastructure

Creates platform level infrastructure components, if required. 

## Required inventory groups

- None

## Optional inventory groups
- `ca_server`
- `db_server`
- `custom_repo`
- `haproxy`
- `krb5_server`

## Plays

### Install custom parcel repository

Applies role [`infrastructure/custom_repo`](/docs/roles/infrastructure/custom_repo.md) to hosts in group `custom_repo`

### Install RDBMS

Applies role [`infrastructure/rdbms`](/docs/roles/infrastructure/rdbms.md) to hosts in group `db_server`

### Install MIT KDC

Applies role [`infrastructure/krb5_server`](/docs/roles/infrastructure/krb5_server.md) to hosts in group `krb5_server`

### Install CA server

Applies role [`infrastructure/ca_server`](/docs/roles/infrastructure/ca_server.md) to hosts in group `ca_server`

### Install HAProxy

Applies role [`infrastructure/haproxy`](/docs/roles/infrastructure/haproxy.md) to hosts in group `haproxy`
