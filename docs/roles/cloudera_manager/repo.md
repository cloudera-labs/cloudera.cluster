
# Cloudera Manager Repository

## Install the default Cloudera Manager version

```
(no extra vars)
```

With no variables overridden, the default behaviour is to install the latest or recommended version of Cloudera Manager (currently `7.0.3`). The version number is specified as `cloudera_manager_version` in the role default variables (`roles/cloudera_manager/repo/defaults/main.yml`).

## Install a custom Cloudera Manager version (public archive, not paywalled)

```
cloudera_manager_version: 6.3.1
```

The version specified in `cloudera_manager_version` is used to construct repository URLs from the public `archive.cloudera.com` repository.

## Install a custom Cloudera Manager version (public archive, paywalled)

```
cloudera_manager_version: 6.3.3
cloudera_manager_repo_username: myusername
cloudera_manager_repo_password: mypassword
```

The version specified in `cloudera_manager_version` is used to construct repository URLs from the public `archive.cloudera.com` repository. Because `cloudera_manager_repo_username` is defined, the role knows to add credentials to the repository details when installing them.

To avoid entering plaintext credentials, use Ansible vault encrypted values, e.g.

```
cloudera_manager_version: 6.3.3
cloudera_manager_repo_username: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          6534653166 ... snip ...
cloudera_manager_repo_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          3338663739 ... snip ...
```

## Install a custom Cloudera Manager version (custom archive)

### Method 1:

If the custom archive follows the same directory structure as Cloudera's public archive, it is possible to set a base URL
and a version. This method is OS agnostic. For example, if deploying on RHEL or CentOS 7, the playbook will automatically append
the `redhat7/yum` portion of the final repo location.

```
cloudera_archive_base_url: http://cloudera-build-us-west-1.vpc.cloudera.com/s3/build/2535749
cloudera_manager_version: 7.1.1
```

### Method 2:

If the custom archive does not follow the same directory structure as Cloudera's public archive, we can totally override the
repository location. Note: `cloudera_manager_repo_url` takes precedence over `cloudera_manager_version`. Any specified version number is ignored when a custom repository URL is set in this manner.

```
cloudera_manager_repo_url: http://cloudera-build-us-west-1.vpc.cloudera.com/s3/build/2400091/cm7/7.1.1/redhat7/yum/
```
