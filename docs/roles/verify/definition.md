# Definition Verification

This role asserts expectations on the cluster definition.

Here we focus on the clusters in aggregation.

Examples include:
- Ensure that TLS is configured in the inventory when specified in a cluster.
- Each host template in the definition is matched to hosts in the inventory and vice versa.
- All KTS/KMS configurations are set as expected.
- Kerberos is enabled when Ranger or Sentry is present in the cluster.

This will catch high-level errors when creating cluster definitions.
