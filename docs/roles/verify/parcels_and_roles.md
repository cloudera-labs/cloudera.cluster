# Parcels and Roles Verification

The role ensures the service and roles configured in each cluster pass a number of basic assertions.

For each cluster, this role downloads the manifest of each repository and, combining this with a service-role mapping, verifies that the services and roles configured in each cluster matches the parcels included.

Here we focus on individual clusters.

Examples include:
- Ensure that all services configured match the parcels services.
- Ensure that all roles configured have the correct parent service
- Ensure that all roles in `configs` are included in the templates.

This will catch many systematic errors when creating cluster definitions.
