# Playbook: Prepare for security

Install required software packages and apply pre-requisite configurations for Kerberos authentication.

## Required inventory groups
- `cloudera_manager`
- `cluster`

## Plays

### Install pre-requisite packages for Kerberos

Applies role [`prereqs/kerberos`](/docs/roles/prereqs/kerberos.md) to hosts in group `cloudera_manager` and `cluster`

### Configure Cloudera Manager server for Kerberos

Runs role [`cloudera_manager/config`](/docs/roles/cloudera_manager/config.md) locally to send the following configuration to Cloudera Manager API:
```
KDC_HOST:       "{{ krb5_kdc_host }}"
KDC_TYPE:       "{{ krb5_kdc_type }}"
KRB_ENC_TYPES:  "{{ krb5_enc_types }}"
SECURITY_REALM: "{{ krb5_realm }}"
```

### Import KDC admin creds to Cloudera Manager

Runs role [`security/import_kdc_admin_creds`](/docs/roles/security/import_kdc_admin_creds.md) locally, only when variable `krb5_kdc_admin_user` is defined.
