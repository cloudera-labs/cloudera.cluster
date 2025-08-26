==============================
cloudera.cluster Release Notes
==============================

.. contents:: Topics

v5.0.0
======

Major Changes
-------------

- Remove collection dependencies from legacy roles (https://github.com/cloudera-labs/cloudera.cluster/pull/324)

Minor Changes
-------------

- Add CM service config module and reconciliation utilities (https://github.com/cloudera-labs/cloudera.cluster/pull/257)
- Add ECS Control plane cluster functionality (https://github.com/cloudera-labs/cloudera.cluster/pull/251)
- Add External Account Module (https://github.com/cloudera-labs/cloudera.cluster/pull/264)
- Add External_user_mappings module (https://github.com/cloudera-labs/cloudera.cluster/pull/248)
- Add Host Config Module (https://github.com/cloudera-labs/cloudera.cluster/pull/234)
- Add Host Template Module (https://github.com/cloudera-labs/cloudera.cluster/pull/238)
- Add Umami tracking to header (https://github.com/cloudera-labs/cloudera.cluster/pull/318)
- Add User Module (https://github.com/cloudera-labs/cloudera.cluster/pull/252)
- Add ansible-lint configuration and remove from pre-commit hooks (https://github.com/cloudera-labs/cloudera.cluster/pull/320)
- Add api-design.md write up (https://github.com/cloudera-labs/cloudera.cluster/pull/277)
- Add cm kerberos module (https://github.com/cloudera-labs/cloudera.cluster/pull/273)
- Add cm_autotls module (https://github.com/cloudera-labs/cloudera.cluster/pull/263)
- Add control_plane and control_plane_info modules (https://github.com/cloudera-labs/cloudera.cluster/pull/312)
- Add documentation for fixture factories for integration testing (https://github.com/cloudera-labs/cloudera.cluster/pull/279)
- Add file name to JSON parsing error message (https://github.com/cloudera-labs/cloudera.cluster/pull/249)
- Add lookup plugin cm_license for parsing Cloudera Manager license files (https://github.com/cloudera-labs/cloudera.cluster/pull/274)
- Add pre-commit instructions (https://github.com/cloudera-labs/cloudera.cluster/pull/240)
- Add pytest fixtures for constructing supporting test resources (https://github.com/cloudera-labs/cloudera.cluster/pull/256)
- Add repository to Hatch docs:changelog script (https://github.com/cloudera-labs/cloudera.cluster/pull/321)
- Add retry logic on HTTP 400 errors for parcel functions (https://github.com/cloudera-labs/cloudera.cluster/pull/288)
- Add return value to wait_for_command_state (https://github.com/cloudera-labs/cloudera.cluster/pull/271)
- Data Context Module (https://github.com/cloudera-labs/cloudera.cluster/pull/246)
- Refactor service_role and service_role_info to align to current flow, utilities, and testing (https://github.com/cloudera-labs/cloudera.cluster/pull/278)
- Rename service_role and service_role_info modules (https://github.com/cloudera-labs/cloudera.cluster/pull/293)
- Rename service_role_config_group and service_role_config_group_info modules (https://github.com/cloudera-labs/cloudera.cluster/pull/294)
- Update Python shebang and documentation organization (https://github.com/cloudera-labs/cloudera.cluster/pull/290)
- Update cm_service module (https://github.com/cloudera-labs/cloudera.cluster/pull/265)
- Update collection version to 4.5.0-rc1 (https://github.com/cloudera-labs/cloudera.cluster/pull/266)
- Update configuration reconciliation logic (https://github.com/cloudera-labs/cloudera.cluster/pull/286)
- Update control_plane API documentation (https://github.com/cloudera-labs/cloudera.cluster/pull/322)
- Update copyright date (https://github.com/cloudera-labs/cloudera.cluster/pull/323)
- Update documentation and changelog management (https://github.com/cloudera-labs/cloudera.cluster/pull/292)
- Update host and host_info modules for cluster membership and role assignments  (https://github.com/cloudera-labs/cloudera.cluster/pull/283)
- Update host_template module and tests (https://github.com/cloudera-labs/cloudera.cluster/pull/281)
- Update retry to timeouts for host and parcel management (https://github.com/cloudera-labs/cloudera.cluster/pull/289)
- Update service and service_info modules to align with current utilities (https://github.com/cloudera-labs/cloudera.cluster/pull/280)
- Update service_role_config_group to align with CM modules (https://github.com/cloudera-labs/cloudera.cluster/pull/272)
- Update service_role_config_group_info module to align with existing modules (https://github.com/cloudera-labs/cloudera.cluster/pull/270)
- Update to cm-client v57 (https://github.com/cloudera-labs/cloudera.cluster/pull/326)
- add test script (https://github.com/cloudera-labs/cloudera.cluster/pull/254)

Deprecated Features
-------------------

- Deprecate MySQL filters (https://github.com/cloudera-labs/cloudera.cluster/pull/309)
- Deprecate append_database_port filter (https://github.com/cloudera-labs/cloudera.cluster/pull/300)
- Deprecate cluster_service_role_hosts filter (https://github.com/cloudera-labs/cloudera.cluster/pull/301)
- Deprecate cm_api action (https://github.com/cloudera-labs/cloudera.cluster/pull/299)
- Deprecate default_database_port filter (https://github.com/cloudera-labs/cloudera.cluster/pull/302)
- Deprecate extract_* filters (https://github.com/cloudera-labs/cloudera.cluster/pull/303)
- Deprecate filter_null_configs filter (https://github.com/cloudera-labs/cloudera.cluster/pull/304)
- Deprecate find_clusters filter (https://github.com/cloudera-labs/cloudera.cluster/pull/305)
- Deprecate flatten_dict_list filter (https://github.com/cloudera-labs/cloudera.cluster/pull/306)
- Deprecate format_database_type filter (https://github.com/cloudera-labs/cloudera.cluster/pull/308)
- Deprecate host_config and host_config_info modules (https://github.com/cloudera-labs/cloudera.cluster/pull/298)
- Deprecate legacy roles (https://github.com/cloudera-labs/cloudera.cluster/pull/311)
- Deprecate service_config and service_config_info modules (https://github.com/cloudera-labs/cloudera.cluster/pull/297)
- Deprecate service_role_config and service_role_config_info modules (https://github.com/cloudera-labs/cloudera.cluster/pull/296)
- Deprecate service_role_config_group_config and service_role_config_group_config_info modules (https://github.com/cloudera-labs/cloudera.cluster/pull/295)
- Deprecate to_ldap_type_enum filter (https://github.com/cloudera-labs/cloudera.cluster/pull/310)
- Deprecate version filters (https://github.com/cloudera-labs/cloudera.cluster/pull/307)

Security Fixes
--------------

- Add no_log to sensitive parameters (https://github.com/cloudera-labs/cloudera.cluster/pull/287)

Bugfixes
--------

- Change 'tls' parameter to 'auto_tls'  (https://github.com/cloudera-labs/cloudera.cluster/pull/285)
- Create Mgmt Role model utility for CMS (https://github.com/cloudera-labs/cloudera.cluster/pull/282)
- Fix external_user_mapping module (https://github.com/cloudera-labs/cloudera.cluster/pull/313)
- Hotfix/cluster module (https://github.com/cloudera-labs/cloudera.cluster/pull/244)
- Remove invalid get_host_ref() (https://github.com/cloudera-labs/cloudera.cluster/pull/284)
- Update cm_utils discover_endpoint function (https://github.com/cloudera-labs/cloudera.cluster/pull/253)
- Update normalization to use type() not isinstance() checks (https://github.com/cloudera-labs/cloudera.cluster/pull/275)
- Update version of upload-artifact action (https://github.com/cloudera-labs/cloudera.cluster/pull/269)

New Plugins
-----------

Lookup
~~~~~~

- cloudera.cluster.cm_license - Get the details of a Cloudera license.

New Modules
-----------

- cloudera.cluster.cm_autotls - Manage and configure Auto-TLS and Cloudera Manager CA.
- cloudera.cluster.cm_autotls_info - Retrieve Cloudera Manager configurations for Auto-TLS.
- cloudera.cluster.cm_kerberos - Manage and configure Kerberos Authentication for CDP.
- cloudera.cluster.cm_kerberos_info - Retrieve Cloudera Manager configurations for Kerberos.
- cloudera.cluster.cm_service_role - Manage a Cloudera Manager Service role.
- cloudera.cluster.cm_service_role_config_group - Manage a Cloudera Manager Service role config group.
- cloudera.cluster.cm_service_role_config_group_info - Retrieve information about Cloudera Management service role config groups.
- cloudera.cluster.cm_service_role_info - Retrieve information about Cloudera Management service roles.
- cloudera.cluster.control_plane - Manage Cloudera control planes.
- cloudera.cluster.data_context - Create, update, or delete a data context.
- cloudera.cluster.data_context_info - Retrieve details of data contexts.
- cloudera.cluster.deprecation - Display a deprecation warning.
- cloudera.cluster.external_account - Create, update, or delete an external module account.
- cloudera.cluster.external_account_info - Retrieve external account details details.
- cloudera.cluster.external_user_mappings - Create, update, or delete external user mappings.
- cloudera.cluster.external_user_mappings_info - Retrieve details of external user mappings.
- cloudera.cluster.host_template - Manage a cluster host template.
- cloudera.cluster.host_template_info - Retrieve details regarding a cluster's host templates.

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
