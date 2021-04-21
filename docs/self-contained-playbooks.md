# Self-Contained Playbooks

This doc provides brief set of instructions on how to create and utilise a self-contained "playbook" distro. The main idea is to create a virtual environment with cloudera-playbook itself, Ansible and its dependencies that can be packaged and used later for an on-site installation.

## Why we might need a self-contained playbook:

- networking restrictions (e.g. VPN + jump host that has to be used for the installation) that make it impossible to run playbook from our laptop or other controlled environment
- customer requirement to work from their laptop/VDI/workstation
- customer requirement to have all bits and pieces used for the install
- sticking to specific versions of ansible, python, etc. for reproducible installs

## What is being packaged:

- the playbook itself
- ansible
- ansible dependencies
- ansible galaxy roles playbook depends on
- python (might not be strictly required)

It's questionable whether python has to be part of the distribution since all operating systems supported by Cloudera platform have python available.

## How to prepare a package (with Python):

Prepare the package on the OS version that's going to be used during the playbook run. E.g. if you are going to install the cluster from a RHEL7 jump host, spinup a RHEL7 VM and create the package on that VM.

```
# Create a working directory (you'll have to use the same absolute path when using the package)
mkdir -p /opt/cloudera/playbook-env

# install python from source
yum install yum-utils make wget
yum-builddep python
wget https://www.python.org/ftp/python/3.8.2/Python-3.8.2.tgz
tar -xvf Python-3.8.2.tgz
cd Python-3.8.2
./configure --prefix=/opt/cloudera/playbook-env/python && make && make install

# install virtualenv
cd /opt/cloudera/playbook-env
python/bin/pip3 install virtualenv

# create virtual environment for ansible
python/bin/virtualenv ansible-venv

# install ansible
cd ansible-venv/
source bin/activate
pip install ansible==2.9.7
pip install jmespath

# clone playbook
git clone https://github.com/cloudera-labs/cloudera.cluster.git

# install roles from ansible galaxy required by the playbook to ansible-venv directory
ansible-galaxy install --roles-path ./galaxy_roles -r cloudera.cluster/requirements.yml

# test everything works as expected
# cd cloudera.cluster/
# ANSIBLE_ROLES_PATH=../galaxy_roles ansible-playbook -i examples/sample/hosts --extra-vars @examples/sample/extra_vars.yml create_infrastructure.yml

# clean things up
cd /opt/cloudera/
find ./playbook-env/ -name "*.pyc" -delete
rm -rf playbook-env/ansible-venv/cloudera.cluster/.git

# create an archive
tar -zcvf /tmp/playbook-env-with-python.tbz /opt/cloudera/playbook-env
```

## How to prepare a package (without Python):

```
# Create a working directory (you'll have to use the same absolute path when using the package)
mkdir -p /opt/cloudera/playbook-env

# install virtualenv
cd /opt/cloudera/playbook-env
python/bin/pip3 install virtualenv

# create virtual environment for ansible
python/bin/virtualenv ansible-venv

# install ansible
cd ansible-venv/
source bin/activate
pip install ansible==2.9.7
pip install jmespath

# clone playbook
git clone https://github.com/cloudera-labs/cloudera.cluster.git

# install roles from ansible galaxy required by the playbook to ansible-venv directory
ansible-galaxy install --roles-path ./galaxy_roles -r cloudera.cluster/requirements.yml

# test everything works as expected
# cd cloudera.cluster/
# ANSIBLE_ROLES_PATH=../galaxy_roles ansible-playbook -i examples/sample/hosts --extra-vars @examples/sample/extra_vars.yml create_infrastructure.yml

# clean things up
cd /opt/cloudera/
find ./playbook-env/ -name "*.pyc" -delete
rm -rf playbook-env/ansible-venv/cloudera.cluster/.git

# create an archive
tar -zcvf /tmp/playbook-env-with-python.tbz /opt/cloudera/playbook-env
```

## How to deploy the package:

```
# Extract the archive tar -C/ -xvf playbook-env.tgz
cd /opt/cloudera/playbook-env/ansible-venv/

# Activate the virtual environment
source bin/activate

# Edit extra_vars.yml, cluster.yml and hosts files if needed and run the playbook
ANSIBLE_ROLES_PATH=../galaxy_roles ansible-playbook -i examples/7.1.x/single-node/hosts --extra-vars @examples/7.1.x/single-node/extra_vars.yml site.yml

```

## What's left out of scope:

Given this setup is mostly needed in isolated environments where there's no internet access from cluster node, it's likely that the installation will be performed from a local repository. This is covered pretty well in Cloudera's documentation (e.g. [Configuring a Local Parcel Repository](https://docs.cloudera.com/documentation/enterprise/upgrade/topics/cm_ig_create_local_parcel_repo.html) for CDH5 and CDH6).

There are several OS level dependencies when performing a cluster installation (e.g. Java, Kerberos libraries, rngd). In case of an isolated environment, the customer should have a local repo of some sort where those packages are available (list of requirements is covered in deployment and security prerequisites documents).

In case MySQL database is used as backend, MySQL JDBC driver should be made available in a local repository (mysql_connector_url playbook variable should be modified to point to a local repo url with a zip archive with the driver).



