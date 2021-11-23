# Creating Secure Clusters

## Enabling Kerberos

To enable Kerberos for a cluster, set `kerberos: true` inside the `security` block of its definition.
Kerberos **must** be enabled if you want to include certain services in the cluster, e.g. Ranger or Sentry.

```yaml
clusters:
  - name: CDP PvC Base Cluster
    services: [HDFS, RANGER, SOLR, ZOOKEEPER]
    security:
      kerberos: true
```

If a KDC will be provisioned by the playbook and you are happy with default values for realm names, encryption types etc, no other configuration is required.

## Enabling TLS

To enable TLS for a cluster, the following configurations are required:

1) Set `tls: true` inside the `security` block of its definition.

```yaml
clusters:
  - name: CDP PvC Base Cluster
    services: [HDFS, RANGER, SOLR, ZOOKEEPER]
    security:
      tls: true
```

2) Set `tls: True` on all inventory host groups for which TLS keystores and truststores need to be generated.

```ini
[cluster:vars]
tls=True
```

3a) If you wish to create a standalone CA server and sign certificates against this for a fully automated (but less secure) cluster, add a `[ca_server]` block to the inventory.

```ini
[ca_server]
ca-server-1.example.com
```

3b) If you wish to manually sign certificates against an 
external CA, like Active Directory, add the path where signed certificates will be stored and root CA certificate details in `extra_vars.yml`

```yaml
tls_ca_certs:
  - alias: ScaleAD
    path: /path/to/root/certs/scale-ad.pem

tls_signed_certs_dir: /path/to/signed/certs
```

The directory `tls_signed_certs_dir` should contain PEM format certificates, one per server, named with the FQDN of the host, e.g `host-1.fully.qualified.example.com.pem`

## Enabling HDFS Encryption

To enable HDFS Encryption for a cluster, the following steps must be followed:

1. Set `hdfs_encryption: true` inside the `security` block of the main cluster definition.
2. Add a second cluster definition for Key Trustee Server, marked `type: kts`

Example:

```yaml
clusters:

  - name: CDP PvC Base Cluster
    services: [HDFS, RANGER, SOLR, ZOOKEEPER]
    repositories:
      - 'http://archive/c7/parcel/repo'
    security:
      hdfs_encryption: true

  - name: KTS Cluster
    type: kts
    repositories:
      - 'http://archive/keytrustee-server/parcel/repo'
      - 'http://archive/c7/parcel/repo'
```

**It is not necessary to include KMS services in the cluster service list or host templates.** These will be added for you automatically.

Note: at the moment it is necessary to add a CDH/CDP Private Cloud Base parcel repository to the Key Trustee Server cluster as well as the base cluster, even though no CDH or CDP Private Cloud Base services will run there.

Add the following new blocks to your **inventory** to specify which hosts should be used for Key Trustee and KMS servers.

```ini
[kts_active]
kts-1.example.com

[kts_passive]
kts-2.example.com

[kms_servers]
kms-1.example.com
kms-2.example.com
kms-3.example.com
```

If you do not want Key Trustee Server to be highly available, you can omit the `kts_passive` group (this is **not** recommended).

The KMS group `kms_servers` must have at least one host but can have as many as desired. Unlike KTS, KMS nodes are all active and load balanced.