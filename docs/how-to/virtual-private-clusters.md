# How to: Deploy Virtual Private Clusters

This guide will run through specifics for deploying Virtual Private Clusters.

It assumes you are already familiar with deploying standard clusters using these playbooks.

For a good introduction to Virtual Private Clusters, read the Cloudera blog post [Improving Multi-tenancy with Virtual Private Clusters](https://blog.cloudera.com/improving-multi-tenancy-with-virtual-private-clusters/) by Tom Deane. Also, before you start, review the [Cloudera documentation for VPCs](https://docs.cloudera.com/documentation/enterprise/latest/topics/cm_sdx_vpc.html) to learn about [compatibility considerations](https://docs.cloudera.com/documentation/enterprise/latest/topics/cm_sdx_ki.html) and [performance trade-offs](https://docs.cloudera.com/documentation/enterprise/latest/topics/cm_sdx_vpc.html#concept_ys1_4gz_1hb).


1. **Create a definition containing your base cluster**

Create a cluster definition with a base cluster containing, at least, all of the services you wish to include in the shared data context.

In order for a cluster to serve as the base for VPCs, it must have a **data context**.

Define a `data_contexts` block inside your base cluster definition and provide a list of services which will be shared:

```
clusters:
  - name: Example Base Cluster
 ...
    data_contexts:
      - name: SDX
        services: [HDFS, HIVE, ATLAS, RANGER]
```

> **Note:** A data context called `SDX`, including all sharable services, will be automatically created if no data context is specified.

The name of the data context can be any string, but take note because it is required in the next step.

The services list is also optional. If this is not included, the full set of possible shareable services will be added for you, i.e Hive, HDFS, Sentry (CDH) or Atlas and Ranger (CDP Private Cloud Base).

> **Important**: Your base cluster **must** be configured for HDFS high availability.

2. Add a compute cluster to your definition

A cluster block for a compute cluster (VPC) must have `type: compute`. You must also include a `base_cluster` block, which refers to your base cluster's name and the name of the data context defined there:

```
- name: Example Compute Cluster
  type: compute
...
  base_cluster:
    name: Example Base Cluster
    data_context: SDX
```

Apart from these specific requirements, defining services, repositories, configs and role layouts is done exactly the same way as it would be for base clusters.

> **Important**: If your base cluster is configured for Kerberos, your compute cluster **must** also have Kerberos enabled.

3. **Define your inventory**

For a simple cluster we define inventory groups for master nodes, worker nodes and so on. When working with virtual private clusters we create extra, separate groups for the compute clusters too.

> Important: The `[cluster:children]` group must contain the groups for **all** clusters. This will ensure all servers are initialised correctly, have Cloudera Manager agent installed, etc.

**Example:**
```

[base_master_nodes]
node1.example.com host_template=Base_Master1
node2.example.com host_template=Base_Master2

[base_worker_nodes]
node3.example.com
node4.example.com
node5.example.com

[base_worker_nodes:vars]
host_template=Base_Worker

[vpc_master_nodes]
node6.example.com host_template=VPC_Master1
node7.example.com host_template=VPC_Master2

[vpc_worker_nodes]
node8.example.com
node9.example.com
node10.example.com

[vpc_worker_nodes:vars]
host_template=VPC_Worker

[cluster:children]
base_master_nodes
base_worker_nodes
vpc_master_nodes
vpc_worker_nodes

```

For further information about the `host_template` variables above, see [How to: Connect Inventories to Cluster Definitions](TODO).

4. **Deploy!**
