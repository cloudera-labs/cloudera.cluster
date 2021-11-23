# Inventory files

## Required Groups

### Cloudera Manager

The `cloudera_manager` group must contain a single server which will become the Cloudera Manager server. (Cloudera Manager HA is not supported at this time.)

```ini
[cloudera_manager]
host-1.example.com
```

### Cluster Nodes

A group named `cluster` is **required**. This is the set of nodes which will have a Cloudera Manager agent and receive pre-requisite configurations like OS tuning, database client and JDK installation and Kerberos configs. 

Usually, `cluster` will be composed of child groups like this:

```ini
[cluster:children]
cluster_master_nodes
cluster_worker_nodes
cluster_edge_nodes
```

... with the actual servers being listed like this:

```ini
[cluster_master_nodes]
host-1.example.com host_template=Master1

[cluster_worker_nodes]
host-2.example.com
host-3.example.com
host-4.example.com

[cluster_edge_nodes]
host-5.example.com
host-6.example.com
```

The names of the cluster sub-groups are arbitrary. These are only for convenience when assigning host template names and to make the inventory easier to read and understand. 

#### Assigning Host Templates

The variable `host_template` must be defined against each cluster server. The host template label used must then also be defined in `cluster.yml`, which allows the defined services and roles to be mapped to the individual servers.

```ini
[cluster_worker_nodes]
host-2.example.com host_template=Workers
host-3.example.com host_template=Workers
host-4.example.com host_template=Workers
```

For convenience, it is possible to assign the `host_template` variable to all members of a group using the `group_name:vars` syntax:

```ini
[cluster_worker_nodes]
host-2.example.com
host-3.example.com
host-4.example.com

[cluster_worker_nodes:vars]
host_template=Workers
```

**Important:** it is only possible to assign one host template to a host. If you set the `host_template` variable to a host in one group, then set it again on the same host but in a different inventory group, the first value will be overwritten. For example, when co-locating master and worker roles, you may try the following:

```
[cluster_master_nodes]
host-1.example.com host_template=Master

[cluster_worker_nodes]
host-1.example.com host_template=Workers
```

This does **not** work. Only the `Workers` group will be set in this scenario.

Instead, you must create a merged template in `cluster.yml` containing all the master and worker roles you want to assign in one go, then set this in the inventory like so:

```
[cluster_worker_nodes]
host-1.example.com host_template=MasterWorker
```

## Optional Groups

### CDSW

Servers which will form a Cloudera Data Science Workbench (CDSW) cluster need to be added in the following way. The aggregate group `cdsw` is **important**. This ensures that the special pre-requisite tasks for CDSW are correctly applied.

```ini
[cdsw_master_nodes]
cdsw-1.example.com host_template=CDSW-Master

[cdsw_worker_nodes]
cdsw-2.example.com
cdsw-3.example.com
cdsw-4.example.com

[cdsw_worker_nodes:vars]
host_template=CDSW-Workers

[cdsw:children]
cdsw_master_nodes
cdsw_worker_nodes

[cluster:children]
cluster_master_nodes
cluster_worker_nodes
cdsw
```

### HDFS Encryption (KMS / Key Trustee Server)

Configuring HDFS encryption requires two extra groups `kts_active` and `kms_servers` with a third, optional (but **recommended**) group `kts_passive` to enable Key Trustee Server high availability. 

The `kts_active` and `kts_passive` groups must contain a single node each. The KMS group `kms_servers` must have at least one host but can have as many as desired. 

```ini
[kms_servers]
kms-1.example.com
kms-2.example.com
kms-3.example.com

[kts_active]
kts-1.example.com

[kts_passive]
kts-2.example.com

[cluster:children]
cluster_master_nodes
cluster_worker_nodes
kts_active
kts_passive
kms_servers
```

### Infrastructure

The following host groups are **optional**.

If these are omitted or left empty, the steps to provision these items will be skipped. This is for cases where such infrastructure is already provided and we do not want to create it from scratch.

#### Database server

```ini
[db_server]
host-10.example.com
```

#### Kerberos KDC

```ini
[krb5_server]
host-10.example.com
```

#### Load balancer (HAProxy)

```ini
[haproxy]
host-10.example.com
```

#### TLS CA Server

```ini
[ca_server]
host-10.example.com
```

#### Custom parcel repository

```ini
[custom_repo]
host-10.example.com
```

## Multiple Clusters

It is possible to define multiple clusters in the inventory. The key point is that the `cluster` group must contain **all** servers which will be under Cloudera Manager's control, regardless of which cluster they belong to. 


The inventory group names `cluster1` and `cluster2` are arbitrary. This is just a convenience to make the inventory easier to understand. 

```ini
[cluster1]
host-2.example.com  host_template=Cluster1-Master
host-3.example.com  host_template=Cluster1-Worker
host-4.example.com  host_template=Cluster1-Worker
host-5.example.com  host_template=Cluster1-Worker

[cluster2]
host-6.example.com  host_template=Cluster2-Master
host-7.example.com  host_template=Cluster2-Worker
host-8.example.com  host_template=Cluster2-Worker
host-9.example.com  host_template=Cluster2-Worker

[cluster:children]
cluster1
cluster2
```