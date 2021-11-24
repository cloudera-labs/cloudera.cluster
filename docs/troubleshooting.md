# Troubleshooting

## Common issue #1

```
fatal: [host.example.com]: UNREACHABLE! => {“changed”: false, “msg”: “Failed to connect to the host via ssh: Permission denied (publickey,gssapi-keyex,gssapi-with-mic,password).“, “unreachable”: true}
```

or

```
fatal: [host.example.com]: UNREACHABLE! => {"changed": false, "msg": "SSH password was requested, but none specified", "unreachable": true}
```

**Problem**: 

  - Passwordless SSH connectivity is not correctly set up between your Ansible server and the remote servers in the inventory. 

**Solutions**:

  - _(recommended)_ Create an SSH key pair for the Ansible server and ensure the public key is placed in all the servers' `authorized_keys` file for the connecting user, e.g. `/root/.ssh/authorized_keys` or `/home/<user>/.ssh/authorized_keys`

  - _(alternative)_ Provide a password for SSH connectivity during the playbook run:

    ```bash
    $ ansible-playbook --ask-pass ...other args
    ```

## Common issue #2

```
fatal: [host.example.com]: UNREACHABLE! => {"changed": false, "msg": "Host key checking is enabled, and SSH reported an unrecognized or mismatching host key.", "unreachable": true}
```

**Problem**: 

  - SSH host key checking is enabled (Ansible default) but the servers you are trying to connect to are not present in `known_hosts` (or their key has changed)

**Solutions**:

- _(easiest, but least secure)_ Disable Ansible host key checking. In your Ansible configuration file, enter the following:

  ```ini
  [defaults]
  host_key_checking = False
  ```

- _(annoying, but more secure)_ Connect to each of your servers manually from the Ansible host once, so that the `known_hosts` file becomes populated.

## Common issue #3

```
{"msg": "The task includes an option with an undefined variable. The error was: 'dict object' has no attribute u’some.hostname.com'\n\nThe error appears to be in '/home/ansible/cloudera-playbook/roles/deployment/services/mgmt/tasks/main.yml': line 28, column 3, but may\nbe elsewhere in the file depending on the exact syntax problem.\n\nThe offending line appears to be:\n\n\n- name: Define target host ID for Cloudera Management Service installation\n  ^ here\n"}
```

**Problem**:

The cause is likely to be one of the following:

1) Inconsistent hostname resolution. The Cloudera Manager is reporting itself with a different hostname to that contained in your inventory file. 

2) Cloudera Manager agent(s) are not heartbeating correctly.

**Solution**:

By this stage of the playbook execution, Cloudera Manager server will be running. Log into Cloudera Manager and view the **Hosts** page:

- If hosts appear, check the list to ensure that the hostnames shown match your inventory file. If they do not match, either update your inventory file with these hostnames or update the cluster DNS so that the same names can be resolved consistently everywhere. 

- If no hosts appear, log into the server indicated in the error message, and:

  - Check that the `cloudera-manager-agent` service is running. 

  - Check the Cloudera Manager agent log file `/var/log/cloudera-scm-agent/cloudera-scm-agent.log`. Any error message there should give a clue as to why communication with the Cloudera Manager server is failing. 

## Common issue #4

```
ERROR! couldn't resolve module/action 'cm_api'. This often indicates a misspelling, missing collection, or incorrect module path.
```

**Problem**: 

- The `cm_api` action is not available in a custom role.

**Solution**: 

- Add the following into the role's `meta/main.yml` file.

  ```yaml
  ---
  dependencies:
    - role: cloudera_manager/api_client
  ```