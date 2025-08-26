# Testing cloudera.cluster

This project uses [Hatch](https://hatch.pypa.io/dev/) to manage the project dependencies, testing environments, common utilities and scripts, and other activities. It also makes heavy use of [pytest](https://pytest.org).  We also use [pre-commit](https://pre-commit.com/), [antsibull-docs](https://ansible.readthedocs.io/projects/antsibull-docs/), and [ansible-lint](https://ansible.readthedocs.io/projects/lint/) for linting and hygiene.

To set up a development and test environment for the collection, you need to:

1. Set up the Hatch build system
1. Set up the Ansible Collection and Role paths
1. Configure the PYTHONPATH to use the correct location of the collections code

## Hatch Build System

You should install `hatch` as [per its documentation](https://hatch.pypa.io/dev/install/#installers). `hatch` should be able to handle all dependencies, including Python versions and virtual environments.

> [!danger] OSX `dirs.data` default!
> The [default data directory](https://hatch.pypa.io/1.13/config/hatch/#data) for `hatch` is `~/Library/Application Support/hatch`, which causes trouble for `molecule`! You might need to change this location to a path with spaces!

## Ansible Collection and Role Paths

You have to install your Ansible collections, both the collection under test and its dependencies, into the `ansible_collections/<namespace>/<name>` folder structure.  For the collection under test, run the following _in the parent directory of your choosing_:

```bash
git clone https://github.com/cloudera-labs/cloudera.cluster.git ansible_collections/cloudera/cluster
```

Then create the `roles` directory in this _parent directory_:

```bash
mkdir roles
```

Lastly, set the Ansible [COLLECTION](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#envvar-ANSIBLE_COLLECTIONS_PATH) and [ROLE](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#envvar-ANSIBLE_ROLES_PATH) configurations for these two locations:

```bash
export ANSIBLE_COLLECTIONS_PATH=$(pwd)
export ANSIBLE_ROLES_PATH="$(pwd)/roles"
```

## PYTHONPATH

Make sure to include the `ANSIBLE_COLLECTIONS_PATH` variable to the `PYTHONPATH` to allow module imports.

```bash
export PYTHONPATH="${ANSIBLE_COLLECTIONS_PATH}":"${PYTHONPATH}"
```

# Linting and Commits

The `pre-commit` Python application is used to manage linting and other housekeeping functions. The application is installed as a `git` hook and as a Github workflow check.

Commits and pull requests will fail if your contributions do not pass the `pre-commit` checks.  You can check your work-in-progress code by running the following:

```bash
hatch run lint
```

Or manually:

```bash
pre-commit run -a
```

# pytest Testing

> [!warning] Integration test instructions
> The vast majority of tests require an existing Cloudera on premise deployment as the target. Currently, these instructions are not yet complete!

To see what tests (unit and integration) are available, run the following from the `ANSIBLE_COLLECTIONS_PATH` directory:

```bash
pushd ${ANSIBLE_COLLECTIONS_PATH};
pytest ansible_collections/cloudera/cluster --collect-only;
popd;
```

You should see something like:

```
platform darwin -- Python 3.12.8, pytest-8.4.1, pluggy-1.6.0
rootdir: /Users/wmudge/Devel/collections/ansible_collections/cloudera/cluster
configfile: pyproject.toml
plugins: mock-3.14.1
collected 475 items

<Dir cluster>
  <Dir tests>
    <Package unit>
      <Dir plugins>
        <Dir actions>
          <Dir assemble_cluster_template>
            <Module test_assemble_cluster_template_action.py>
              <Function test_empty_parameters>
              <Function test_missing_src>
              <Function test_missing_dest>
              <Function test_remote_src>
              <Function test_src_not_found>
              <Function test_src_not_directory>
              <Function test_invalid_regexp>
              <Function test_assemble_fragments>
              <Function test_assemble_fragments_regexp>
              <Function test_assemble_fragments_malformed>
        <Dir modules>
          <Dir assemble_cluster_template>
            <Module test_assemble_cluster_template_module.py>
              <Function test_missing_required>
              <Function test_missing_dest>
```

To run all of the tests:

```bash
pushd ${ANSIBLE_COLLECTIONS_PATH};
pytest ansible_collections/cloudera/cluster;
popd;
```

To run a selected test, execute with a regex:

```bash
pushd ${ANSIBLE_COLLECTIONS_PATH};
pytest ansible_collections/cloudera/cluster -k "test_assemble_cluster_template_module"
popd;
```
