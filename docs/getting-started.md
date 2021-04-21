# Getting Started

Before you begin, ensure that Ansible and its dependencies are all properly configured as per the [Requirements](/README.md#requirements).

```
[root@localhost cloudera-playbook]# ansible --version
ansible 2.9.9
  config file = /root/.ansible.cfg
  configured module search path = ['/root/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /usr/local/lib/python3.6/site-packages/ansible
  executable location = /usr/local/bin/ansible
  python version = 3.6.8 (default, Aug  7 2019, 17:28:10) [GCC 4.8.5 20150623 (Red Hat 4.8.5-39)]
```

All the following steps should be done wherever Ansible is installed:

## 1. Clone the repository

If you are working from a fork, replace the repository URL below with your own.

```
$ git clone https://github.com/cloudera-labs/cloudera.cluster.git
$ cd cloudera.cluster
```

## 2. Install dependencies

```
$ ansible-galaxy role install -r requirements.yml
$ ansible-galaxy collection install -r requirements.yml
```

**Ansible 2.9.x or below**

This step is required only when planning to provision database servers. We use roles by [Jeff Geerling](https://github.com/geerlingguy) from [Ansible Galaxy](https://galaxy.ansible.com/) for installing MySQL / MariaDB or PostgreSQL.

**Ansible 2.10.x or above**

Installing dependencies is **always** necessary for 2.10.x because from this version forward, much of Ansible's functionality has been pulled out of core and into [collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html).

The additional Ansible collections required by these playbooks are:

- [`ansible.posix`](https://galaxy.ansible.com/ansible/posix)
- [`community.crypto`](https://galaxy.ansible.com/community/crypto)
- [`community.general`](https://galaxy.ansible.com/community/general)
- [`freeipa.ansible_freeipa`](https://galaxy.ansible.com/freeipa/ansible_freeipa)

## 3. Create a secrets file (optional, but recommended)

Passwords are required at various points during the playbook run. It is recommended to use [Ansible Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html) and create an encrypted file in which to store these passwords and other sensitive variables securely.

To create an encrypted secrets file, use the `ansible-vault` command:

```bash
$ ansible-vault create secrets.yml
```

After choosing a password of your choice an editor opens, add at least the following two variables for Cloudera paywall credentials:

```yaml
vault__cloudera_manager_repo_username: yourusername
vault__cloudera_manager_repo_password: yourpassword
```

> It is recommended to use the prefix `vault__` for your encrypted variable names in order to easily tell them apart from standard, non encrypted variables defined elsewhere.

You could also include a variable containing database passwords, e.g:

```yaml
vault__cloudera_database_passwords:
  scm: password1
  hive: password2
  hue: password3
  oozie: password4
... etc ...
```

The [docs](how-to/database-configuration.md) go through how these database password variables would be used in practice.

If you want to include other passwords/secrets here for use in your config files, then add these to your vault file too.

Closing the editor saves and encrypts the file. We can now store this file a git repository without any risk of exposing the credentials inside.

## 4. Create an environment "definition"

An environment definition is a directory with two files:

- `extra_vars.yml`
- `cluster.yml`

The file `extra_vars.yml` contains general variables to override during playbook execution. Documentation for how these variables affect individual roles is contained in the roles' own documentation page (inside `docs` folder).

The file `cluster.yml` contains special variables specifically for cluster deployment: services, roles and configs.

An example definition is specified in the [samples](../examples/sample) folder. You can use these as a base and customise as required for your own cluster design or requirements.

## 5. Create an inventory file

An inventory file is a grouped list which informs what the playbook will actually do, and to which servers. Some inventory groups are required, others are optional.

Full details can be found in the [inventories](inventories.md) documentation page, and examples are provided inside the `examples` subfolder.

> General guidance about inventories can also be found in [Ansible documentation](https://docs.ansible.com/ansible/latest/user_guide/intro_inventory.html).

## 6. Verify connectivity to your servers

The Ansible node will need to connect to all the servers in your inventory via SSH. By default, Ansible assumes you are using SSH keys to connect to remote machines. This is the recommended method.

If you cannot set up passwordless SSH using keys, and instead you need to enter a password to authenticate, then you must include the `-k/--ask-pass` option to your `ansible-playbook` command and type in the password before the playbook run can start.

## 7. Run core playbooks for deployment

```bash
$ ansible-playbook -i /path/to/your-inventory-file \
  --extra-vars @/path/to/definitions/sample/extra_vars.yml \
  --extra-vars @secrets.yml \
  --ask-vault-pass \
  site.yml
```

> To avoid having to enter a vault password every time, set up a vault password file as explained in [Ansible Vault docs](https://docs.ansible.com/ansible/latest/user_guide/vault.html#providing-vault-passwords).

The `site.yml` playbook imports a number of other playbooks to run a full deployment end-to-end:

### Core playbooks

- [`verify_everything.yml`](playbooks/verify_everything.md)

  Runs a series of pre-deployment checks against the inventory and cluster definition files to surface problems early and prevent failures much later in the process.

- [`create_infrastructure.yml`](playbooks/create_infrastructure.md)

  Creates platform level infrastructure components, if required. Examples: MIT KDC, RDBMS (MariaDB or PostgreSQL), TLS CA server, or HAProxy.

- [`prepare_nodes.yml`](playbooks/prepare_nodes.md)

  Install required software packages and apply pre-requisite operating system configurations.

- [`install_cloudera_manager.yml`](playbooks/install_cloudera_manager.md)

  Install Cloudera Manager Server and agents, configure its database and apply license if available.

- [`prepare_security.yml`](playbooks/prepare_security.md)

  Install required software packages and apply pre-requisite configurations for Kerberos authentication.

- [`install_cluster.yml`](playbooks/install_cluster.md)

  Deploy Cloudera Management Service and a CDH or CDP Private Cloud Base cluster.

- [`setup_hdfs_encryption.yml`](playbooks/setup_hdfs_encryption.md)

  Additional steps to configure HDFS encryption when relevant configs and inventory groups for KMS and Key Trustee servers has been provided.

You are free to run any of these playbooks independently. For example, to only install Cloudera Manager you could run just this playbook in place of `site.yml`:

```
$ cd /path/to/cloudera.cluster
$ ansible-playbook -i /path/to/your-inventory-file \
  --extra-vars @/path/to/definitions/7.1.x/basic/extra_vars.yml \
  --extra-vars @secrets.yml \
  --ask-vault-pass \
  install_cloudera_manager.yml
```

## 8. Run extra playbooks for post-install configuration (optional)

Some playbooks are provided but are not included in `site.yml`.

These are for optional functionality that can be layered onto an existing deployment, such as security or high availability configuration.

### Extra playbooks available

- [`teardown.yml`](playbooks/teardown.md)

  This playbook attempts to clean-up the hosts, that already have clusters installed (or partially installed), to allow to user to install a new environment.

- `enable_autotls.yml`

  Enables Auto-TLS on an existing Cloudera Manager and CDP Private Cloud Base 7.1 environment.
