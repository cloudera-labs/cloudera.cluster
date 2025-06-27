==============================
Cloudera.Cluster Release Notes
==============================

.. contents:: Topics

v4.4.0
======

Minor Changes
-------------

- Add CM Service Info Module (https://github.com/cloudera-labs/cloudera.cluster/pull/190)
- Add CM Service Module  (https://github.com/cloudera-labs/cloudera.cluster/pull/194)
- Add Cloudera Manager config modules (https://github.com/cloudera-labs/cloudera.cluster/pull/211)
- Add Cluster Info Module (https://github.com/cloudera-labs/cloudera.cluster/pull/204)
- Add Host Module (https://github.com/cloudera-labs/cloudera.cluster/pull/218)
- Add Import_cluster_template module (https://github.com/cloudera-labs/cloudera.cluster/pull/197)
- Add License/License_info Module (https://github.com/cloudera-labs/cloudera.cluster/pull/199)
- Add Parcel Module (https://github.com/cloudera-labs/cloudera.cluster/pull/221)
- Add cluster module (https://github.com/cloudera-labs/cloudera.cluster/pull/224)
- Add cluster service and related resource modules (https://github.com/cloudera-labs/cloudera.cluster/pull/220)
- Add cm_trial module (https://github.com/cloudera-labs/cloudera.cluster/pull/195)
- Add or update API to support diff documentation (https://github.com/cloudera-labs/cloudera.cluster/pull/225)
- Add workflow and steps to validate for and publishing to Ansible Galaxy (https://github.com/cloudera-labs/cloudera.cluster/pull/230)
- Update cluster and cluster_info results object and API (https://github.com/cloudera-labs/cloudera.cluster/pull/228)
- Update cluster state management (https://github.com/cloudera-labs/cloudera.cluster/pull/227)
- Update parcel_info API output and move parsing function to parcel_utils (https://github.com/cloudera-labs/cloudera.cluster/pull/226)
- Update to version 4.4.0 (https://github.com/cloudera-labs/cloudera.cluster/pull/231)
- Updates required for publishing collection to Ansible Galaxy (https://github.com/cloudera-labs/cloudera.cluster/pull/229)

Bugfixes
--------

- Remove deprecated ansible.builtin.command 'warn' parameter (https://github.com/cloudera-labs/cloudera.cluster/pull/196)
- Removes blockers to running check mode & diff mode (https://github.com/cloudera-labs/cloudera.cluster/pull/166)
- Update parcels.yml (https://github.com/cloudera-labs/cloudera.cluster/pull/189)
- Update postgresql-RedHat.yml (https://github.com/cloudera-labs/cloudera.cluster/pull/188)

New Modules
-----------

- cloudera.cluster.cluster - Manage the lifecycle and state of a cluster.
- cloudera.cluster.cluster_info - Retrieve details about one or more clusters.
- cloudera.cluster.cm_config - Manage the configuration of Cloudera Manager.
- cloudera.cluster.cm_config_info - Retrieve the Cloudera Manager configuration.
- cloudera.cluster.cm_license - Activate the license for Cloudera Manager.
- cloudera.cluster.cm_license_info - Returns details about current license.
- cloudera.cluster.cm_service - Manage Cloudera Manager service.
- cloudera.cluster.cm_service_config - Manage the Cloudera Manager service configuration.
- cloudera.cluster.cm_service_info - Retrieve information about the Cloudera Management service.
- cloudera.cluster.cm_service_role_config - Manage a service role configuration in cluster.
- cloudera.cluster.cm_service_role_config_group_config - Manage the configuration of a Cloudera Manager Service role config group.
- cloudera.cluster.cm_trial_license - Activate the trial license of Cloudera Manager.
- cloudera.cluster.host - Manage Cloudera Manager hosts.
- cloudera.cluster.host_config - Manage a host configuration in Cloudera Manager.
- cloudera.cluster.host_config_info - Retrieves the configuration details of a specific host.
- cloudera.cluster.host_info - Gather information about Cloudera Manager hosts.
- cloudera.cluster.parcel - Manage the state of parcels on a cluster.
- cloudera.cluster.parcel_info - Gather details about the parcels on the cluster.
- cloudera.cluster.service - Manage a service in cluster.
- cloudera.cluster.service_config - Manage a cluster service configuration.
- cloudera.cluster.service_config_info - Retrieve information about the configuration for a cluster service.
- cloudera.cluster.service_info - Retrieve information about the services of cluster.
- cloudera.cluster.service_role - Manage a service role in cluster.
- cloudera.cluster.service_role_config - Manage a service role configuration in cluster.
- cloudera.cluster.service_role_config_group - Manage a cluster service role config group.
- cloudera.cluster.service_role_config_group_config - Manage the configuration of a cluster service role config group.
- cloudera.cluster.service_role_config_group_config_info - Retrieve the configuration of a cluster service role config group.
- cloudera.cluster.service_role_config_group_info - Retrieve information about a cluster service role config group or groups.
- cloudera.cluster.service_role_config_info - Retrieve information about the configuration for a cluster service role.
- cloudera.cluster.service_role_info - Retrieve information about the service roles of cluster.
- cloudera.cluster.service_type_info - Retrieve the service types of a cluster.
- cloudera.cluster.user - Create, delete or update users within Cloudera Manager.
- cloudera.cluster.user_info - Retrieve user details and associated authentication roles.

v4.3.0
======

Minor Changes
-------------

- Add assemble template role (https://github.com/cloudera-labs/cloudera.cluster/pull/167)
- Update logging and error handling for CM API modules (https://github.com/cloudera-labs/cloudera.cluster/pull/168)
- Update role API for assemble_template (https://github.com/cloudera-labs/cloudera.cluster/pull/183)
- ldap search filters - allow literal expression (https://github.com/cloudera-labs/cloudera.cluster/pull/163)

Bugfixes
--------

- Add changes to run ansible.builtin.template locally (https://github.com/cloudera-labs/cloudera.cluster/pull/170)
- Allow complex expressions in external authentication LDAP search filters (https://github.com/cloudera-labs/cloudera.cluster/pull/171)
- Remove deprecated "warn" argument from shell and command module calls (https://github.com/cloudera-labs/cloudera.cluster/pull/182)

New Roles
---------

- cloudera.cluster.assemble_template - Discover and render files into a cluster template.

v4.2.0
======

Minor Changes
-------------

- Allow selection of cluster deployed from cluster.yml (https://github.com/cloudera-labs/cloudera.cluster/pull/151)
- Create module and action plugins for assemble_cluster_template (https://github.com/cloudera-labs/cloudera.cluster/pull/164)

Bugfixes
--------

- Filter AWS_S3 service from host template validation check (https://github.com/cloudera-labs/cloudera.cluster/pull/161)
- Fix typo - Feature qmanagerdb (https://github.com/cloudera-labs/cloudera.cluster/pull/158)

New Modules
-----------

- cloudera.cluster.assemble_cluster_template - Merge Cloudera Manager cluster template fragments.

v4.1.1
======

Bugfixes
--------

- Remove extra quote from databases-7.1.0 config condition (https://github.com/cloudera-labs/cloudera.cluster/pull/159)

v4.1.0
======

Minor Changes
-------------

- Adds 7.1.9 QueueManager for postgresql (https://github.com/cloudera-labs/cloudera.cluster/pull/152)
- CDH to CDP Upgrade : YARN Queues are not migrated (https://github.com/cloudera-labs/cloudera.cluster/pull/119)
- use spark_on_yarn_service dependency for hive in CDH only (https://github.com/cloudera-labs/cloudera.cluster/pull/123)

v4.0.1
======

Minor Changes
-------------

- Update freeipa.ansible_freeipa collection version (https://github.com/cloudera-labs/cloudera.cluster/pull/134)

Bugfixes
--------

- Move non-controller code in 'module_utils/cm_utils'  (https://github.com/cloudera-labs/cloudera.cluster/pull/136)
- Update validate_pr.yml workflow to install latest ansible-core 2.12.* (https://github.com/cloudera-labs/cloudera.cluster/pull/138)

v4.0.0
======

Minor Changes
-------------

- Add cm_service lookup (https://github.com/cloudera-labs/cloudera.cluster/pull/113)
- Add documentation build workflows (https://github.com/cloudera-labs/cloudera.cluster/pull/125)
- Add query processor to the list of CDP 7.x services (https://github.com/cloudera-labs/cloudera.cluster/pull/85)
- ECS 1.5.0 changes (https://github.com/cloudera-labs/cloudera.cluster/pull/110)
- Fixes for PvC running on PvC with sidecar FreeIPA (https://github.com/cloudera-labs/cloudera.cluster/pull/120)
- Update dependencies for optional functions (https://github.com/cloudera-labs/cloudera.cluster/pull/116)
- Update release/v4.0.0 (#130) (https://github.com/cloudera-labs/cloudera.cluster/pull/132)
- Update release/v4.0.0 (https://github.com/cloudera-labs/cloudera.cluster/pull/130)
- Update with collected CDP PVC changes (https://github.com/cloudera-labs/cloudera.cluster/pull/107)
- support CDP 7.1.9 / CM 7.11.3 deployment (https://github.com/cloudera-labs/cloudera.cluster/pull/127)

Bugfixes
--------

- Add 'freeipa_enroll' optional parameter  (https://github.com/cloudera-labs/cloudera.cluster/pull/129)
- Add Postgres default log_directory (https://github.com/cloudera-labs/cloudera.cluster/pull/114)
- Add missing cm_client library (https://github.com/cloudera-labs/cloudera.cluster/pull/121)
- Add status check for NetworkManager updates (https://github.com/cloudera-labs/cloudera.cluster/pull/115)
- Fix/#111 (https://github.com/cloudera-labs/cloudera.cluster/pull/112)

New Plugins
-----------

Lookup
~~~~~~

- cloudera.cluster.cm_service - Get the details for a service on a CDP Datahub cluster.

New Modules
-----------

- cloudera.cluster.cm_endpoint_info - Discover the Cloudera Manager API endpoint.
- cloudera.cluster.cm_resource - Create, update, and delete resources from the Cloudera Manager API endpoint.
- cloudera.cluster.cm_resource_info - Retrieve resources from the Cloudera Manager API endpoint.
- cloudera.cluster.cm_version_info - Gather information about Cloudera Manager.

v3.4.2
======

Bugfixes
--------

- Remove bindep requirements for community.general.ipa_user (https://github.com/cloudera-labs/cloudera.cluster/pull/105)
- Update ansible-builder installation file logic (https://github.com/cloudera-labs/cloudera.cluster/pull/106)

v3.4.1
======

Minor Changes
-------------

-  #81 add SAN support for certificates (https://github.com/cloudera-labs/cloudera.cluster/pull/82)
- #76 add LIVY for SPARK3 support (https://github.com/cloudera-labs/cloudera.cluster/pull/77)
- Cloudera Manager module framework (https://github.com/cloudera-labs/cloudera.cluster/pull/62)
- Fixes for RHEL8.6 support and custom_repo with Cloudera Manager (https://github.com/cloudera-labs/cloudera.cluster/pull/83)
- Moved host configs out of the cluster role (https://github.com/cloudera-labs/cloudera.cluster/pull/60)
- Pull Request workflow and ansible-builder support (https://github.com/cloudera-labs/cloudera.cluster/pull/104)
- Update collection version to 4.0.0-alpha1 (https://github.com/cloudera-labs/cloudera.cluster/pull/72)
- Updates for private IP installations (https://github.com/cloudera-labs/cloudera.cluster/pull/93)
- WIP PvC Prereqs and Control Plane merge (https://github.com/cloudera-labs/cloudera.cluster/pull/61)

Bugfixes
--------

- #65 Fix SPARK3_ON_YARN inter-service dependency (https://github.com/cloudera-labs/cloudera.cluster/pull/66)
- #86 fix atlas_dir permissions (https://github.com/cloudera-labs/cloudera.cluster/pull/87)
- Avoid repeating CM password check (https://github.com/cloudera-labs/cloudera.cluster/pull/91)
- Remove body_format parameter for parcel manifest URI (https://github.com/cloudera-labs/cloudera.cluster/pull/98)
- Remove body_format parameter for parcel manifest URI (https://github.com/cloudera-labs/cloudera.cluster/pull/99)
- condition based on runtime version (https://github.com/cloudera-labs/cloudera.cluster/pull/75)
- database_port variable typo (https://github.com/cloudera-labs/cloudera.cluster/pull/68)

v3.4.0
======

Minor Changes
-------------

- 2021 07 freeipa dep fix (https://github.com/cloudera-labs/cloudera.cluster/pull/40)
- Adding support for SQL Stream Builder deployment (https://github.com/cloudera-labs/cloudera.cluster/pull/48)
- Fix CA cipher and python2/3 install for newer OS targets like el8 (https://github.com/cloudera-labs/cloudera.cluster/pull/51)
- Pvc experiences (https://github.com/cloudera-labs/cloudera.cluster/pull/44)

v3.3.0
======

Minor Changes
-------------

- Add Ozone data directories (https://github.com/cloudera-labs/cloudera.cluster/pull/54)
- Fixed MariaDB template evaluation used for TLS (https://github.com/cloudera-labs/cloudera.cluster/pull/45)
- Fixed handling of custom roleConfig Groups (https://github.com/cloudera-labs/cloudera.cluster/pull/46)
- Helpful errors (https://github.com/cloudera-labs/cloudera.cluster/pull/42)
- Improve CSD Download (https://github.com/cloudera-labs/cloudera.cluster/pull/53)
- Pin collection versions (https://github.com/cloudera-labs/cloudera.cluster/pull/52)
- Verify if the hostname reported by the agent heartbeat is correct. (https://github.com/cloudera-labs/cloudera.cluster/pull/50)
- removed invalid ranger configs (https://github.com/cloudera-labs/cloudera.cluster/pull/43)

v3.2.0
======

Minor Changes
-------------

- Changes required for Core Settings clusters (https://github.com/cloudera-labs/cloudera.cluster/pull/41)

v3.1.0
======

Minor Changes
-------------

- Add collection dependencies (https://github.com/cloudera-labs/cloudera.cluster/pull/6)
- Fix ansible-galaxy license statement (https://github.com/cloudera-labs/cloudera.cluster/pull/2)
- Home directory mode fix (https://github.com/cloudera-labs/cloudera.cluster/pull/8)
- Update include_role statements to use the full role name within the Collection as a best practice (https://github.com/cloudera-labs/cloudera.cluster/pull/11)

v3.0.3
======

New Plugins
-----------

Filter
~~~~~~

- cloudera.cluster.append_database_port - append_database_port.
- cloudera.cluster.cluster_service_role_hosts - cluster_service_role_hosts.
- cloudera.cluster.default_database_port - default_database_port.
- cloudera.cluster.extract_parcel_urls - extract_parcel_urls.
- cloudera.cluster.extract_products_from_manifests - extract_products_from_manifests.
- cloudera.cluster.filter_null_configs - fill_null_configs.
- cloudera.cluster.find_clusters - find_clusters.
- cloudera.cluster.format_database_type - format_database_type.
- cloudera.cluster.get_database_collation_mysql - get_database_collation_mysql.
- cloudera.cluster.get_database_encoding_mysql - get_database_encoding_mysql.
- cloudera.cluster.get_major_version - get_major_version.
- cloudera.cluster.get_product_version - get_product_version.
- cloudera.cluster.to_ldap_type_enum - to_ldap_type_enum.

v2.0.0
======

New Plugins
-----------

Filter
~~~~~~

- cloudera.cluster.flatten_dict_list - flatten_dict_list.
