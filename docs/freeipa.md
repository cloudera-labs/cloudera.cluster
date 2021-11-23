# FreeIPA

FreeIPA is a product that provides (not exhaustive):

- CA
- KDC
- LDAP
- Host management (including SSSD)

The playbook is able to provision a FreeIPA server, or use an existing FreeIPA server, and automatically setup the cluster to make use of the CA, KDC and LDAP.

Before continuing, a few questions you may want to ask yourself are:

1. Are you using an existing FreeIPA server(s) or do you want the playbook to provision one?
2. Do you want to use the FreeIPA CA to sign the certificates or do you want to sign them externally?
3. Are you using AutoTLS or do you want the playbook to configure the host keys and certificates?

## Common steps

Regardless of how you choose to use FreeIPA in your deployment, you'll have to set the following variables via extra vars:

- `krb5_realm` (e.g. `CLOUDERA.LOCAL`)
- `krb5_kdc_admin_user` (e.g. the FreeIPA default `admin@{{ krb5_realm }}`)
- `krb5_kdc_admin_password` (e.g. `{{ ipaadmin_password }}`)
- `krb5_enc_types` (e.g. `aes256-cts aes128-cts`)

You must also set `krb5_kdc_type: "Red Hat IPA"`.

## Existing FreeIPA or playbook-provisioned?

### Existing FreeIPA

This case is simple:

Please set `krb5_kdc_host` to you FreeIPA server hostname.

### Playbook-provisioned

Here, you'll need to add a host to `krb5_server` and set the following variables:

- `ipaadmin_password`
- `ipadm_password`

The playbook will recognize that `krb5_kdc_type` is set to `Red Hat IPA` and bring up a FreeIPA server instead of MIT KDC.

The playbook will not provision a firewall around the FreeIPA server.

## FreeIPA CA signed certificates or externally signed certificates?

In both cases, you'll want to refer to each CA certificate used (particularly important if you are using a different CA) by adding entries to `tls_ca_certs` e.g. (IPA CA)

```
tls_ca_certs:
  - path: /etc/ipa/ca.crt
    alias: ipaca
```

### FreeIPA CA signed certificates

Here, nothing has to be done.

Provided each host is enrolled as a FreeIPA client then the playbook will automatically sign (~~and enable the renewal of~~ ZOOKEEPER-3832) the host certificates using the hosts principal.

### Externally signed certificates

In this case, please set `skip_ipa_signing` to `true`.

This will cause the playbook to stop after generating CSRs – identical to the non-FreeIPA case.

## AutoTLS or playbook configured?

### AutoTLS

#### CM provisioned CA

Remove any mention of TLS from the cluster definition and enable AutoTLS using the API or wizard.

You may need to add the FreeIPA to the CA certs (via the API or wizard).

#### FreeIPA or externally provisioned certificates

Here, you'll want to unset any TLS configurations in the `cluster.yml` file. This is because AutoTLS takes on the role of configuring the cluster here.

You'll then need to enable AutoTLS using the certificates provisioned (by default) under `/opt/cloudera/security/pki` using the API https://blog.cloudera.com/auto-tls-in-cloudera-data-platform-data-center/ immediately after installing the Cloudera Manager.

You can then continue with the playbook installation.

## LDAP configs

To setup LDAP in CM and services automatically, we'll need to first define an auth provider.

For FreeIPA, it might look something like:

```
base_dn: "dc={{ (krb5_realm | lower).split('.') | join(',dc=') }}"
user_dn: "cn=users,cn=accounts,{{ base_dn }}"
group_dn: "cn=groups,cn=accounts,{{ base_dn }}"

auth_providers:
  freeipa:
    ldap_bind_user_dn: "uid=admin,{{ user_dn }}"
    ldap_bind_password: "{{ ipaadmin_password }}"
    ldap_search_base:
      user: "{{ user_dn }}"
      group: "{{ group_dn }}"
    ldap_object_class:
      user: "person"
      group: "groupofnames"
    ldap_attribute:
      user: "uid"
      group: "cn"
      member: "member"
    type: LDAP
    ldap_url: "ldaps://{{ groups.krb5_server | first }}"
```

Once the auth provider is defined, we need to configure the playbook to use it to:

Configure CM:

```
cloudera_manager_external_auth:
  provider: freeipa
  external_first: yes
  external_only: no
  role_mappings:
  - group: CMTestGroup1
    roles: [ROLE_ADMIN]
```

Configure the services:

```
service_auth_provider: freeipa
```

## YCloud

YCloud will work, but you will need to change the group running `systemd` (not pretty):

`yum install -y gdb && yes | gdb -p 1 --ex 'call setgid(0)' --ex quit`
