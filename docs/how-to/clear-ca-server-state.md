# How to: Clear CA Server state

The CA Server (using `openssl ca`) can be used to sign the host certificates used to deploy the cluster.

There may be cases where you wish to replace the host keys and certificates.

# Replace the CA

On each host in the cluster, move or delete the following directory:

```
/opt/cloudera/security/pki
```

On the `ca_server` host, move or delete the following directory:

```
/ca
```

Re-run the playbook.

At a minimum, re-run the following in the order they appear:

- `create_infrastructure.yml`
- `prepare_tls.yml`

# Keep the CA but replace host certificates

On each host in the cluster where you wish to replace the host keys and certificates, move or delete the following directory:

```
/opt/cloudera/security/pki
```

On the `ca_server` host, execute the following for each host you wish to replace:

```
openssl ca -config /ca/intermediate/openssl.cnf -revoke /ca/intermediate/cert/<host-certificate>.pem -passin pass:<ca-password>
```

__Note:__ The default CA password is `password` and can be configured by setting:

- `ca_server_root_key_password`
- `ca_server_intermediate_key_password`

Now move or delete the corresponding host certificates from:

```
/ca/intermediate/cert
```

Re-run the playbook.

At a minimum, re-run `prepare_tls.yml`.

__Note:__ You can skip the revoke step by setting `unique_subject` in `/ca/intermediate/index.txt.attr` to `no`.

__Note:__ The CA Server is meant for testing only. Please use an enterprise CA Server in production.
