# How to: Add nodes to an existing cluster

This guide will run through specifics for adding nodes to existing clusters.

# Prereqs
The following prerequisites must be fulfilled :
- New nodes up & running
- New nodes connected to Cloudera Manager (Agents installed, configured & running)

The same way as for fresh install or upgrade:
- New nodes are part of the inventory and member of the group 'cluster'
- Host templates must be assigned to the new nodes

# Configuration
Two variables to configure:
```yaml
nodes_addition_host_templates_prefix: Prefix to be used for Host Templates name in Cloudera Manager (i.e. {{ nodes_addition_host_templates_prefix }}+{{ host_template_name_from_definition }})
nodes_addition_hosts:
  - cluster_name: Cluster Name to add below nodes to
    hosts: List of hostnames to add to the above cluster
```
Example values:
```yaml
nodes_addition_host_templates_prefix: "nodes-addition-HostTemplate-"
nodes_addition_hosts:
  - cluster_name: "Basic Cluster"
    hosts: "{{ groups.new_worker_nodes }}"
```

Example inventory:
```ini
...
[cluster_worker_nodes]
worker-001.lab.local
worker-002.lab.local
worker-003.lab.local

[cluster_worker_nodes:vars]
host_template=Workers

[new_worker_nodes]
worker-004.lab.local
worker-005.lab.local
worker-006.lab.local

[new_worker_nodes:vars]
host_template=Workers

[cluster:children]
...
cluster_worker_nodes
new_worker_nodes
```

# Deployment
Run the role nodes_addition
Example playbook:
```yaml
- name: Add new nodes
  hosts: cloudera_manager
  roles:
    - cloudera.cluster.deployment.nodes_addition
```
