# cloudera.cluster - Cloudera on premise and Cloudera Manager

[![API documentation](https://github.com/cloudera-labs/cloudera.cluster/actions/workflows/publish_docs.yml/badge.svg?branch=main&event=push)](https://github.com/cloudera-labs/cloudera.cluster/actions/workflows/publish_docs.yml)

`cloudera.cluster` is an Ansible collection that lets you manage your **[Cloudera Platform](https://www.cloudera.com/products/cloudera-data-platform.html) on premise (Private Cloud)** resources and interact with Cloudera Manager for both on premise installations and cloud Data Hub deployments. With this collection, you can:

* Manager clusters, from `base` to `compute`
* Manage services like Impala, NiFi, Ranger, and Ozone
* Configure Cloudera Manager and `cm_agent`-enabled hosts

If you have any questions, want to chat about the collection's capabilities and usage, need help using the collection, or just want to stay updated, join us at our [Discussions](https://github.com/cloudera-labs/cloudera.cluster/discussions).

## Quickstart

See the [API documentation](https://cloudera-labs.github.io/cloudera.cluster/) for details for each plugin and role within the collection.

1. [Install the collection](#installation)
2. [Install the requirements](#requirements)
3. [Use the collection](#using-the-collection)

## Roadmap

If you want to see what we are working on or have pending, check out:

*  the [Milestones](https://github.com/cloudera-labs/cloudera.cluster/milestones) and [active issues](https://github.com/cloudera-labs/cloudera.cluster/issues?q=is%3Aissue+is%3Aopen+milestone%3A*) to see our current activity,
* the [issue backlog](https://github.com/cloudera-labs/cloudera.cluster/issues?q=is%3Aopen+is%3Aissue+no%3Amilestone) to see what work is pending or under consideration, and
* read up on the [Ideas](https://github.com/cloudera-labs/cloudera.cluster/discussions/categories/ideas) we have in mind.

Are we missing something? Let us know by [creating a new issue](https://github.com/cloudera-labs/cloudera.cluster/issues/new) or [posting a new idea](https://github.com/cloudera-labs/cloudera.cluster/discussions/new?category=ideas)!

## Contribute

For more information on how to get involved with the `cloudera.cluster` Ansible collection, head over to [CONTRIBUTING.md](CONTRIBUTING.md).

## Installation

To install the `cloudera.cluster` collection, you have several options.

The preferred method is to install via Ansible Galaxy; in your `requirements.yml` file, add the following:

```yaml
collections:
  - name: cloudera.cluster
```

If you want to install from GitHub, add to your `requirements.yml` file the following:

```yaml
collections:
  - name: https://github.com/cloudera-labs/cloudera.cluster.git
    type: git
    version: main
```

And then run in your project:

```bash
ansible-galaxy collection install -r requirements.yml
```

You can also install the collection directly:

```bash
# From Ansible Galaxy
ansible-galaxy collection install cloudera.cluster
```

```bash
# From GitHub
ansible-galaxy collection install git+https://github.com/cloudera-labs/cloudera.cluster.git@main
```

`ansible-builder` can discover and install all Python dependencies - current collection and dependencies - if you wish to use that application to construct your environment. Otherwise, you will need to read each collection and role dependency and follow its installation instructions.

See the [Collection Metadata](https://ansible.readthedocs.io/projects/builder/en/latest/collection_metadata/) section for further details on how to install (and manage) collection dependencies.

You may wish to use a _virtual environment_ to manage the Python dependencies.

## Using the Collection

This collection is designed to interact with only the Cloudera Manager endpoint -- on cloud and on premise.  It is decidedly _non-opinionated_ -- that is, these roles and plugins do not make any assumptions about supporting resources and configurations.

Once installed, reference the collection in playbooks and roles.

For example, here we use the
[`cloudera.cluster.service` module](https://cloudera-labs.github.io/cloudera.cluster/service_module.html) to manage the HDFS service for a base cluster, specifically the _service-wide_ configurations and 3 _role configuration groups_:

```yaml
- hosts: localhost
  connection: local
  gather_facts: no
  tasks:
    - name: Establish HDFS service
      cloudera.cluster.service:
        host: "cm.example.internal"
        port: 80
        username: admin
        password: "{{ admin_password }}"
        cluster: my-base-cluster
        name: my-hdfs
        type: HDFS
        config:
          dfs_encrypt_data_transfer_algorithm: AES/CTR/NoPadding
          hadoop_secure_web_ui: true
          core_connector: "my-cluster-core-settings-name"
        role_config_groups:
          - type: DATANODE
            config:
              dfs_data_dir_list: "/dfs/dn"
          - type: NAMENODE
            config:
              dfs_name_dir_list: "/dfs/nn"
          - type: SECONDARYNAMENODE
            config:
              fs_checkpoint_dir_list: "/dfs/snn"
      register: __hdfs
```

## Building the API Documentation

To create a local copy of the API documentation, first make sure the collection is in your `ANSIBLE_COLLECTIONS_PATH`.

```bash
hatch run docs:build
```

Your local documentation will be found at `docsbuild/build/html`.

You can also lint the documentation with the following command:

```bash
hatch run docs:lint
```

## Preparing a New Version

To prepare a version release, first set the following variables for `antsichaut`:

```bash
export GITHUB_TOKEN=some_gh_token_value # Read-only scope
```

Update the collection version using [`hatch version`](https://hatch.pypa.io/latest/version/). For example, to increment to the next _minor_ release:

```bash
hatch version minor
```

Then update the changelog to query the pull requests since the last release.

```bash
hatch run docs:changelog
```

You can then examine (and update if needed) the resulting `changelog.yaml` and `CHANGELOG.rst` files before committing to the release branch.

## License and Copyright

Copyright 2025, Cloudera, Inc.

```
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
