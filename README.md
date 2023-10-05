# cloudera.cluster - Cloudera Data Platform (CDP) for Private Cloud and Cloudera Manager (CM)

[![API documentation](https://github.com/cloudera-labs/cloudera.cluster/actions/workflows/publish_docs.yml/badge.svg?branch=main&event=push)](https://github.com/cloudera-labs/cloudera.cluster/actions/workflows/publish_docs.yml)

`cloudera.cluster` is an Ansible collection that lets you manage your **[Cloudera Data Platform (CDP)](https://www.cloudera.com/products/cloudera-data-platform.html) Private Cloud** resources and interact with Cloudera Manager for both Private Cloud installations and Public Cloud Data Hub deployments. With this collection, you can:

* Create and manage [Private Cloud](https://www.cloudera.com/products/cloudera-data-platform.html) deployments and Public Cloud [Data Hubs](https://www.cloudera.com/products/data-hub.html), including:
  * Manage services like Impala, NiFi, and Ozone
  * Configure Cloudera Manager and `cm_agent`-enabled hosts

If you have any questions, want to chat about the collection's capabilities and usage, need help using the collection, or just want to stay updated, join us at our [Discussions](https://github.com/cloudera-labs/cloudera.cluster/discussions).

## Quickstart

1. [Install the collection](#installation)
2. [Install the requirements](#requirements)
3. [Use the collection](#using-the-collection)

## API

See the [API documentation](https://cloudera-labs.github.io/cloudera.cluster/) for details for each plugin and role within the collection. 

## Roadmap

If you want to see what we are working on or have pending, check out:

*  the [Milestones](https://github.com/cloudera-labs/cloudera.cluster/milestones) and [active issues](https://github.com/cloudera-labs/cloudera.cluster/issues?q=is%3Aissue+is%3Aopen+milestone%3A*) to see our current activity,
* the [issue backlog](https://github.com/cloudera-labs/cloudera.cluster/issues?q=is%3Aopen+is%3Aissue+no%3Amilestone) to see what work is pending or under consideration, and
* read up on the [Ideas](https://github.com/cloudera-labs/cloudera.cluster/discussions/categories/ideas) we have in mind.

Are we missing something? Let us know by [creating a new issue](https://github.com/cloudera-labs/cloudera.cluster/issues/new) or [posting a new idea](https://github.com/cloudera-labs/cloudera.cluster/discussions/new?category=ideas)!

## Contribute

For more information on how to get involved with the `cloudera.cluster` Ansible collection, head over to [CONTRIBUTING.md](CONTRIBUTING.md).

## Installation

To install the `cloudera.cluster` collection, you have several options. Please note that we have not yet published this collection to the public Ansible Galaxy server, so you cannot install it via direct namespace, rather you must specify by Git project and (optionally) branch.

### Option #1: Install from GitHub

Create or edit your `requirements.yml` file in your project with the
following:

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
ansible-galaxy collection install git+https://github.com/cloudera-labs/cloudera.cluster.git@main
```

### Option #2: Install the tarball

Periodically, the collection is packaged into a distribution which you can
install directly:

```bash
ansible-galaxy collection install <collection-tarball>
```

See [Building the Collection](#building-the-collection) for details on creating a local tarball.

## Requirements

`cloudera.cluster` expects `ansible-core>=2.10,<2.13`.

> [!WARNING]
> The current `import_template` functionality does not yet work with Ansible version `2.13` and later.

The collection has the following _required_ dependencies:

| Name | Type | Version |
|------|------|---------|
| `ansible.posix` | collection | `1.3.0` |
| `community.crypto` | collection | `2.2.1` |
| `community.general` | collection | `4.5.0` |

There are a number of _optional_ dependencies for the collection:

| Name | Type | Version |
|------|------|---------|
| `community.mysql` | collection | `3.1.0` |
| `community.postgresql` | collection | `1.6.1` |
| `freeipa.ansible_freeipa` | collection | `1.11.1` |
| `geerlingguy.postgresql` | role | `2.2.0` |
| `geerlingguy.mysql` (patched) | role | `master` |

The collection also requires the following Python libraries to operate its modules:

  * [jmespath](https://jmespath.org/)
  * [cm_client](https://cloudera.github.io/cm_api/docs/python-client-swagger/)

The collection's Python dependencies alone, _not_ the required Python libraries of its collection dependencies, are in `requirements.txt`.

All collection dependencies, required and optional, can be found in `requirements.yml`; only the _required_ dependencies are in `galaxy.yml`. `ansible-galaxy` will install only the _required_ collection dependencies; you will need to add the _optional_ collection dependencies as needed (see above). 

`ansible-builder` can discover and install all Python dependencies - current collection and dependencies - if you wish to use that application to construct your environment. Otherwise, you will need to read each collection and role dependency and follow its installation instructions.

See the [Collection Metadata](https://ansible.readthedocs.io/projects/builder/en/latest/collection_metadata/) section for further details on how to install (and manage) collection dependencies.

You may wish to use a _virtual environment_ to manage the Python dependencies.

See the `base` *Execution Environment* configuration in [`cloudera-labs/cldr-runner`](https://github.com/cloudera-labs/cldr-runner) as an example of how you can install the optional dependencies to suit your specific needs.

## Using the Collection

This collection is designed to work hand-in-hand with the [`cloudera-deploy` application](https://github.com/cloudera-labs/cloudera-deploy), which uses reference playbooks from the [`cloudera.exe` collection](https://github.com/cloudera-labs/cloudera.exe) and example definitions. Coming releases will decouple these collections further while maintaining backwards compatibility.

Once installed, reference the collection in your playbooks and roles.

For example, here we use the
[`cloudera.cluster.cm_resource` module](https://cloudera-labs.github.io/cloudera.cluster/cm_resource_module.html) to patch the Hue service with updated Knox proxy hosts:

```yaml
- hosts: localhost
  connection: local
  gather_facts: no
  vars:
    cm_api:  "{{ lookup('ansible.builtin.env', 'CM_API') }}"
    user:    "{{ lookup('ansible.builtin.env', 'CM_USERNAME') }}"
    pwd:     "{{ lookup('ansible.builtin.env', 'CM_PASSWORD') }}"
    cluster: "my-cluster"
  tasks:
    - name: Update Hue SSO (Knox Proxies)
      cloudera.cluster.cm_resource:
        url: "{{ cm_api }}"
        username: "{{ user }}"
        password: "{{ pwd }}"
        path: "v51/clusters/{{ cluster }}/services/hue/config"
        method: PUT
        parameters:
          message: "Patch Knox proxy hosts for Hue (Ansible)"
        body:
          items:
            - name: knox_proxyhosts
              value: "{{ ['master1', 'master2', 'master3'] | join(',') }}"
```

## Building the Collection

To create a local collection tarball, run:

```bash
ansible-galaxy collection build 
```

## Building the API Documentation

To create a local copy of the API documentation, first make sure the collection is in your `ANSIBLE_COLLECTIONS_PATHS`. Then run the following:

```bash
# change into the /docsbuild directory
cd docsbuild

# install the build requirements (antsibull-docs); you may want to set up a
# dedicated virtual environment
pip install ansible-core https://github.com/cloudera-labs/antsibull-docs/archive/cldr-docsite.tar.gz

# Install the collection's build dependencies
pip install requirements.txt

# Then run the build script
./build.sh
```

Your local documentation will be found at `docsbuild/build/html`.

## Tested Platforms

Active development is focused on **CDP Private Cloud** deployments and their respective platform compatibility matrices.

> [!NOTE]
> While the collection's plugins and roles can be used to deploy CDH 5.x and CDH 6.x environments, it is only possible to install a subset of their supported platform components (i.e JDK and database versions) using this tooling.

### Cloudera Distributions

- Cloudera Manager / CDP Private Cloud Base 7.1.x
- Cloudera Manager / CDP Private Cloud Base 7.0.3 (limited support)
- Cloudera Manager / CDH 6.x
- Cloudera Manager / CDH 5.x (limited support)

### Operating Systems

- Red Hat / CentOS 7.x
- Red Hat / CentOS 8.x
- Ubuntu 18.04 LTS (Bionic Beaver)
- Ubuntu 20.04 LTS (Focal Fossa)

## Operational Features

> [!WARNING]
> These operational features are deprecated as of version 4.x. If you want to use or build similar features and functions, head over to the [Discussions](https://github.com/cloudera-labs/cloudera.cluster/discussions) to learn more about using the collection to achieve your platform operations needs.

This collection includes support for:

- Upgrading Cloudera Manager Server and Cloudera Manager Agents
- Upgrading CDH 5 and/or CDH6 to CDP Private Cloud Base
- Refreshing the config for running clusters, including adding new services or updating the config of existing services.

These features are potentially very dangerous and can cause damage to running clusters if used incorrectly. If you plan to use these features, please ensure that you test thoroughly on a disposable environment.

Cloudera recommends that Cloudera Professional Services be engaged before using these features, particularly as none of these operational features are covered under Cloudera Support agreements.

In order to use these capabilities you will need some permutation of the following variables:
- `cloudera_runtime_pre_upgrade` (specify the version of the legacy cluster - e.g. 5.16.2)
- `update_services` (true if you want to update the config of existing services)
- `upgrade_kts_cluster` (true to upgrade a kts cluster)
- `activate_runtime_upgrade` (true to do a patch release activation)
- `cdh_cdp_upgrade` (true to do a CDH to CDP upgrade)
- `upgrade_runtime` (true to upgrade between versions of CDH or CDP)

## License and Copyright

Copyright 2023, Cloudera, Inc.

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
