# Playbook: Teardown

This playbook tears down hosts that already have clusters installed (or partially installed), to allow to user to install a new environment.

## Configuration options

The teardown playbook supports the following options:

- `teardown_everything`
- `teardown_cluster`
- `teardown_cms`
- `teardown_skip_cluster_deletion`
- `skip_cdsw_teardown`
- `teardown_preserve_parcels`
- `teardown_skip_daemon_package_deletion`

The value you should set each of these configs to depends on what you are hoping to achieve with the teardown.

__Note:__ `teardown_skip_cluster_deletion` is discussed at the bottom of this page.

__Note:__ `teardown_preserve_parcels` stops the Cloudera Manager agents deleting the parcel content on cluster deletion. This should only be used in testing but can greatly reduce the time taken during the re-installation of a cluster.

__Note:__ `teardown_skip_daemon_package_deletion` stops the teardown playbook from removing the daemon package. It can be used generally, provided the Cloudera Manager versions match. This flag reduces the time taken during the re-installation of a cluster (in the case where the Cloudera Manager server and agents are removed).

### Full teardown

If you want to teardown each cluster, the CMS service, agents and the Cloudera Manager server, please set:
```
teardown_everything=true
```

Examples of when this might be useful include:
- Installing a completely different DEV environment on existing hosts.
- Re-installing a similar environment, but with the TLS or Kerberos configuration modified.

### Cluster teardown

If you want to teardown a single cluster, leaving all other clusters, the CMS service, agents and the Cloudera Manager server intact, please set:
```
teardown_cluster='<cluster_name>'
```
where `<cluster_name>` is replaced with the name of the cluster you wish to teardown.

If you want to teardown every single cluster, leaving the CMS service, agents and the Cloudera Manager server intact, please set:
```
teardown_cluster=all
```
instead.

Examples of when this might be useful include:
- Re-installing a cluster following a failure during it's first run.
- Re-installing a cluster following changes to service configurations.

### CMS teardown

If you want to teardown the CMS service in CM, leaving all clusters, agents and the server intact, please set:

```
teardown_cms=true
```

## Running the playbook tasks

Once you've decided how you are going to configure the teardown, you'll want to prepare a copy of the definition for the existing environment, already installed on the hosts (you can use the definition of the new environment if this is unavailable).

Finally, start the teardown process by running:
```shell
ansible-playbook -i path/to/hosts \
  --extra-vars=@path/to/definition/extra_vars.yml \
  --extra-vars="<teardown_configs>" \
  /path/to/playbook/teardown.yml
```
where `<teardown_configs>` is replaced by the teardown configs you are using (space separated).

_For example_, if you wanted to teardown a cluster named `Cluster1`, you may run something like:
```shell
ansible-playbook -i hosts \
  --extra-vars=@example_definitions/simple/extra_vars.yml \
  --extra-vars="teardown_cluster='Cluster1'" \
  cloudara-playbook-v2/teardown.yml
```

Once running, the playbook will:
- Attempt to stop and delete each cluster (that is included in the teardown) from the Cloudera Manager server.
- Scan the environment's definition for databases that are included in the teardown and either:
  * Remove the database if the database host is controlled by the playbook
  * (__important__) Warn the user that the database must be deleted manually.
- Scan the environment's definition for key directories that are included in the teardown and are known to cause problems during re-installation and remove them from the hosts.
- Stop the agent and Cloudera Manager server services and remove the packages from the hosts, in the case where `teardown_everything=true`.

After the playbook is finished, you should be able to continue with your planned re-installation.

## Important notes and limitations

- The teardown playbook is (understandably) quite __destructive__. Please carefully consider the impact before executing the playbook.
- The teardown playbook does not clean hosts. It will remove databases and directories that would otherwise cause the next installation to fail but there will still be a number of files left from the original environment. If this is required, then you should clean the disks and re-install the OS.
- In the case that the Cloudera Manager server and/or agents are not healthy, the playbook may be unable to stop and delete the clusters. Even with `teardown_everything=true`, this error is fatal as stopping the cluster helps clean-up the running processes. If you still wish to continue with the teardown, you can set `teardown_skip_cluster_deletion=true` but please reboot the hosts after the teardown to clean-up the running processes.
- If you are tearing down an environment in order to change the major version of the Cloudera Manager server, please reboot the hosts before containing with the re-installation.
