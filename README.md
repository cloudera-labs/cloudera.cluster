# Ansible Playbooks for Cloudera Data Platform

## Requirements

- Python 2.x or 3.x
- [Ansible](http://docs.ansible.com/ansible/intro_installation.html)
- [JMESPath](https://jmespath.org/)

**Do not use Ansible 2.9.0**. This version has an [issue with templating](https://github.com/ansible/ansible/issues/64745) which causes the playbook execution to fail. Instead, use any 2.8.x version or a later 2.9.x version as these are not affected.

## Supported Platforms

### Cloudera Distributions

- Cloudera Manager / CDP Private Cloud Base 7.1.x
- Cloudera Manager / CDP Private Cloud Base 7.0.3 (limited support)
- Cloudera Manager / CDH 6.x
- Cloudera Manager / CDH 5.x (limited support)

### Operating Systems

- Red Hat / CentOS 7.x
- Ubuntu 18.04.04 LTS (Bionic Beaver)

Active development is focused on **CDP Private Cloud Base** (formerly CDP-DC) deployments and their respective platform compatibility matrices.

> While these playbooks can be used to deploy CDH 5.x and CDH 6.x environments, it is only possible to install a subset of their supported platform components (i.e JDK and database versions) using this tool.

## Getting Started

For help setting up the playbook, creating configs and deploying clusters, see the [Getting Started](docs/getting-started.md) guide.

## How-to Guides

For more detailed information, check the following guides:

* Deploying [secure clusters](docs/security.md)
* Deploying [data contexts (SDX) and virtual private clusters](docs/how-to/virtual-private-clusters.md)

## Help!

Common issues and their solutions are documented on the [Troubleshooting](docs/troubleshooting.md) page. Check here first.

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
