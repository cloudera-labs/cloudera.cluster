# Playbook Verify Definition

Checks a number of assertion against the inventory, cluster definition and the parcels used. This playbook can be run in complete isolation of the hosts, provided the parcels can still be accessed.

The goal of this playbook is to reduce the number of runtime failures.

## Plays

Before running any of the verify roles, `verify_everything.yml` groups the hosts by their host template using the `group_by` module. This step does not required connectivity to the hosts themselves.

### Checks Inventory

Runs role [`verify/inventory`](/docs/roles/verify/inventory.md) locally

### Checks Cluster Definition

Runs role [`verify/definition`](/docs/roles/verify/definition.md) locally

### Checks Services, Roles and Parcels

Runs role [`verify/parcels_and_roles`](/docs/roles/verify/parcels_and_roles.md) locally
