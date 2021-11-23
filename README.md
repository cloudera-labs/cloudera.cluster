# Ansible Collection for Cloudera Private Cloud

## Requirements

- Python 2.x or 3.x
- [Ansible](http://docs.ansible.com/ansible/intro_installation.html)
- [JMESPath](https://jmespath.org/)

**Do not use Ansible 2.9.0**. This version has an [issue with templating](https://github.com/ansible/ansible/issues/64745) which causes the playbook execution to fail. Instead, use any 2.8.x version or a later 2.9.x version as these are not affected.

## Usage
This Ansible Collection is designed to work hand-in-hand with [Cloudera Deploy](https://github.com/cloudera-labs/cloudera-deploy), which contains reference Playbooks and Example Definitions.

## Tested Platforms

### Cloudera Distributions

- Cloudera Manager / CDP Private Cloud Base 7.1.x
- Cloudera Manager / CDP Private Cloud Base 7.0.3 (limited support)
- Cloudera Manager / CDH 6.x
- Cloudera Manager / CDH 5.x (limited support)

### Operating Systems

- Red Hat / CentOS 7.x and 8.x
- Ubuntu 18.04 LTS (Bionic Beaver) and 20.04 LTS (Focal Fossa)

Active development is focused on **CDP Private Cloud Base** (formerly CDP-DC) deployments and their respective platform compatibility matrices.

> While these roles etc. can be used to deploy CDH 5.x and CDH 6.x environments, it is only possible to install a subset of their supported platform components (i.e JDK and database versions) using this tooling.

## How do I contribute code?
You need to first sign and return an
[ICLA](icla/Cloudera_ICLA_25APR2018.pdf)
and
[CCLA](icla/Cloudera_CCLA_25APR2018.pdf)
before we can accept and redistribute your contribution. Once these are submitted you are
free to start contributing to cloudera-playbook. Submit these to CLA@cloudera.com.

### Main steps
* Fork the repo and create a topic branch
* Push commits to your repo
* Create a pull request!

### Find
We use Github issues to track bugs for this project. Find an issue that you would like to
work on (or file one if you have discovered a new issue!). If no-one is working on it,
assign it to yourself only if you intend to work on it shortly.

### Fix

Please write a good, clear commit message, with a short, descriptive title and
a message that is exactly long enough to explain what the problem was, and how it was
fixed.

## Copyright

(C) Cloudera, Inc. 2021 All rights reserved.

## License
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

# IMPORTANT NOTICE:

This release includes support for:
- Upgrading Cloudera Manager Server and Cloudera Manager Agents
- Upgrading CDH 5 and/or CDH6 to CDP Private Cloud Base
- Refreshing the config for running clusters, including adding new services or updating the config of existing services.

These features are potentially very dangerous and can cause damage to running clusters if used incorrectly. If you plan to use these features, please ensure that you test thoroughly on a disposable environment, before running on clusters that are not disposable.

Cloudera recommends that Cloudera Professional Services be engaged before using these features, particularly as none of the automation products are covered under your Cloudera Support agreements.

In order to use these capabilities you will need some permutation of the following variables:
- `cloudera_runtime_pre_upgrade` (specify the version of the legacy cluster - e.g. 5.16.2)
- `update_services` (true if you want to update the config of existing services)
- `upgrade_kts_cluster` (true to upgrade a kts cluster)
- `activate_runtime_upgrade` (true to do a patch release activation)
- `cdh_cdp_upgrade` (true to do a CDH to CDP upgrade)
- `upgrade_runtime` (true to upgrade between versions of CDH or CDP)
