#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2024 Cloudera, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

DOCUMENTATION = r"""
module: cluster
short_description: Manage the lifecycle and state of a cluster
description:
  - Enables cluster management, cluster creation, deletion, and unified control of all services of a cluster.
  - Create or delete cluster in Cloudera Manager.
  - Start or stop all services inside the cluster.
  - If provided the C(template) parameter, the module will populate its parameters using the cluster template contents.
  - Any other parameters will merge on top of the parameters declared by the cluster template.
author:
  - "Ronald Suplina (@rsuplina)"
  - "Webster Mudge (@wmudge)"
requirements:
  - cm-client
options:
  name:
    description:
      - The cluster name.
    type: str
    required: yes
    aliases:
      - cluster_name
  cluster_version:
    description:
      - The runtime version of the cluster.
    type: str
    required: no
  type:
    description:
      - The type of cluster.
    type: str
    required: no
    choices:
      - BASE_CLUSTER
      - COMPUTE_CLUSTER
      - EXPERIENCE_CLUSTER
  state:
    description:
      - The state of the cluster.
      - If I(state=absent), the cluster's services will be shut down first, then the cluster deleted.
    type: str
    required: no
    default: present
    choices:
      - present
      - absent
      - stopped
      - started
      - restarted
  template:
    description:
      - A cluster template file to populate the module parameters, e.g. as a baseline.
    type: path
    required: no
    aliases:
      - cluster_template
  add_repositories:
    description:
      - Flag to add any repositories found in a cluster template should be added to Cloudera Manager.
      - Valid only if I(template) is set.
    type: bool
    required: no
    default: no
  maintenance:
    description:
      - Flag enabling the maintenance mode for the cluster.
    type: bool
    required: no
    aliases:
      - maintenance_enabled
  services:
    description:
      - List of services and service configurations to enable for the cluster.
    type: list
    elements: dict
    required: no
    suboptions:
      name:
        description:
          - The name or reference of the service.
          - If not set, a name for the service will be auto-generated.
        type: str
        required: no
        aliases:
          - ref
          - ref_name
      type:
        description:
          - The type of service to enable.
        type: str
        required: yes
      version:
        description:
          - The version of the service to enable.
        type: str
        required: no
      config:
        description:
          - The service configuration values, i.e. the "service-wide" configuration.
        type: dict
        required: no
      role_groups:
        description:
          - List of role configuration groups for a role type of the service.
          - Both base and custom role configuration groups are supported.
        type: list
        elements: dict
        required: no
        aliases:
          - role_config_groups
        suboptions:
          name:
            description:
              - The name of the role group.
              - If not set, the base role group, i.e. the default role group, for the role type is used.
            type: str
            required: no
            aliases:
              - ref
              - ref_name
          type:
            description:
              - The role type for the role group.
            type: str
            required: yes
            aliases:
              - role_type
          display_name:
            description:
              - The display name of the role group in the Cloudera Manager UI.
              - If not set, the I(name) will be used.
            type: str
            required: no
          config:
            description:
              - The role group configuration values.
            type: dict
            required: no
      display_name:
        description:
          - The display name of the service in the Cloudera Manager UI.
          - If not set, the I(name) will be used.
        type: str
        required: no
      tags:
        description:
          - The tags labeling the service.
        type: dict
        required: no
  hosts:
    description:
      - List of hosts and their configuration attached to the cluster.
    type: list
    elements: dict
    required: no
    suboptions:
      name:
        description:
          - The hostname or host ID of the host.
        type: str
        required: yes
        aliases:
          - host_id
          - hostname
      config:
        description:
          - The host configuration values.
        type: dict
        required: no
      host_template:
        description:
          - The host template to apply to the host.
        type: str
        required: no
      role_groups:
        description:
          - List of role groups to associate directly with the host.
        type: list
        elements: dict
        aliases:
          - role_config_groups
        suboptions:
          name:
            description:
              - The name of the custom role group.
              - Mutually exclusive with I(type).
            type: str
            required: no
            aliases:
              - ref
              - ref_name
          service:
            description:
              - The name of the service associated with the role group.
            type: str
            required: yes
            aliases:
              - service_name
              - service_ref
          type:
            description:
              - The role type of the base role group for the service.
              - Mutually exclusive with I(name).
            type: str
            required: no
            aliases:
              - role_type
      roles:
        description:
          - List of per-host role instance configuration overrides.
        type: list
        elements: dict
        required: no
        suboptions:
          service:
            description:
              - The name of the service of the role instance.
            type: str
            required: yes
            aliases:
              - service_name
              - service_ref
          type:
            description:
              - The role type of the role instance.
            type: str
            required: yes
            aliases:
              - role_type
          config:
            description:
              - The role instance override configuration values.
            type: dict
            required: yes
      tags:
        description:
          - The tags labeling the host.
        type: dict
        required: no
  host_templates:
    description:
      - List of host template definitions for the cluster for use with hosts.
    type: list
    elements: dict
    required: no
    suboptions:
      name:
        description:
          - The name of the host template.
        type: str
        required: yes
      role_groups:
        description:
          - List of role groups, base and custom, to associated with the host template.
        type: list
        elements: dict
        aliases:
          - role_config_groups
        suboptions:
          name:
            description:
              - The name of the custom role group.
              - Mutually exclusive with I(type).
            type: str
            required: no
            aliases:
              - ref
              - ref_name
          service:
            description:
              - The name of the service associated with the role group.
            type: str
            required: yes
            aliases:
              - service_name
              - service_ref
          type:
            description:
              - The role type of the base role group for the service.
              - Mutually exclusive with I(name).
            type: str
            required: no
            aliases:
              - role_type
  control_plane:
    description:
      - Private Cloud Control Plane on embedded kubernetes
    type: dict
    required: no
    suboptions:
      remote_repo_url:
        description:
          - The url of the remote repository where the private cloud artifacts to install are hosted.
        type: str
        required: yes
      datalake_cluster_name:
        description:
          - The name of the datalake cluster to use for the initial environment in this control plane.
        type: str
        required: yes
      control_plane_config:
        description:
          - A yaml structured dictionary with configuration parameters for the installation.
        type: dict
        required: yes
        aliases:
          - values_yaml
  parcels:
    description:
      - The parcels by version enabled for a cluster.
      - The name of the parcel is the c(key), the version of the parcel is the c(value).
    type: dict
    required: no
  tags:
    description:
      - The tags labeling the cluster.
    type: dict
    required: no
  display_name:
    description:
      - The name of the cluster in the Cloudera Manager UI.
      - If not set, the I(name) of the cluster will be used.
    type: str
    required: no
  contexts:
    description:
      - List of data contexts for compute-type clusters.
      - Required if I(type=COMPUTE_CLUSTER).
    type: list
    elements: str
    required: no
    aliases:
      - data_contexts
  auto_tls:
    description:
      - Flag enabling TLS for the cluster.
    type: bool
    required: no
    aliases:
      - tls_enabled
      - cluster_tls
  auto_assign:
    description:
      - Flag enabling the auto-assignment of role in the cluster.
      - This function honors existing or declared assignments.
    type: bool
    required: no
    default: no
    aliases:
      - auto_assign_roles
extends_documentation_fragment:
  - ansible.builtin.action_common_attributes
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - cloudera.cluster.purge
  - cloudera.cluster.message
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  platform:
    platforms: all
"""

EXAMPLES = r"""
- name: Create a minimal cluster (can be used by other modules to establish services, etc.)
  cloudera.cluster.cluster:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: 7180
    cluster_name: example-cluster
    cluster_version: "7.1.9"
    cluster_type: BASE_CLUSTER
    state: present

- name: Start all services on a cluster
  cloudera.cluster.cluster:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: example-cluster
    state: started

- name: Delete a Cluster
  cloudera.cluster.cluster:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: example-cluster
    state: absent

- name: Create a cluster with a direct assignment of a base role group
  cloudera.cluster.cluster:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: example-host-assignment-base
    cluster_version: "7.1.9"
    type: BASE_CLUSTER
    state: present
    services:
      - name: ROLE_GROUP_ASSIGNMENT
        type: ZOOKEEPER
        role_groups:
          - type: SERVER
            display_name: Server Base Group
            config:
              zookeeper_server_java_heapsize: 134217728 # 128MB
          - name: DIRECT_ROLE_GROUP_ASSIGNMENT
            type: SERVER
            display_name: Server Custom Group
            config:
              zookeeper_server_java_heapsize: 33554432  # 32MB
    hosts:
      - name: worker-02.cldr.internal
        role_groups:
          - type: SERVER
            service: ROLE_GROUP_ASSIGNMENT

- name: Create a cluster with a direct assignment of a custom role group
  cloudera.cluster.cluster:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: example-host-assignment-custom
    cluster_version: "7.1.9"
    type: BASE_CLUSTER
    state: present
    services:
      - name: ROLE_GROUP_ASSIGNMENT
        type: ZOOKEEPER
        role_groups:
          - type: SERVER
            display_name: Server Base Group
            config:
              zookeeper_server_java_heapsize: 134217728 # 128MB
          - name: DIRECT_ROLE_GROUP_ASSIGNMENT
            type: SERVER
            display_name: Server Custom Group
            config:
              zookeeper_server_java_heapsize: 33554432  # 32MB
    hosts:
      - name: worker-02.cldr.internal
        role_groups:
          - type: SERVER
            name: DIRECT_ROLE_GROUP_ASSIGNMENT

- name: Create a cluster with a per-host override of a role configuration
  cloudera.cluster.cluster:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: example-host-override
    cluster_version: "7.1.9"
    type: BASE_CLUSTER
    state: present
    services:
      - name: ZK-EXAMPLE
        type: ZOOKEEPER
        role_groups:
          - name: NON-BASE-SERVER
            type: SERVER
            display_name: Server Custom Group
            config:
              zookeeper_server_java_heapsize: 75497472  # 72MB
    hosts:
      - name: worker-01.cldr.internal
        roles:
          - service: ZK-EXAMPLE
            type: SERVER
            config:
              zookeeper_server_java_heapsize: 67108864 # 64MB
        host_template: Example_Template
    host_templates:
      - name: Example_Template
        role_groups:
          - NON-BASE-SERVER
    parcels:
      CDH: "7.1.9"

- name: Create and establish a minimal base cluster
  cloudera.cluster.cluster:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    name: Basic_Cluster
    cluster_version: "7.1.9-1.cdh7.1.9.p0.44702451"
    type: BASE_CLUSTER
    state: started
    services:
      - name: core-settings-0
        type: CORE_SETTINGS
        display_name: Core Settings
      - name: zookeeper-0
        type: ZOOKEEPER
        display_name: Zookeeper
        config:
          zookeeper_datadir_autocreate: yes
      - name: hdfs-0
        type: HDFS
        config:
            zookeeper_service: zookeeper-0
            core_connector: core-settings-0
        role_groups:
          - type: DATANODE
            config:
              dfs_data_dir_list: /dfs/dn
          - type: NAMENODE
            config:
              dfs_name_dir_list: /dfs/nn
          - type: SECONDARYNAMENODE
            config:
              fs_checkpoint_dir_list: /dfs/snn
      - name: yarn-0
        type: YARN
        config:
          hdfs_service: hdfs-0
          zookeeper_service: zookeeper-0
        role_groups:
          - type: RESOURCEMANAGER
            config:
              yarn_scheduler_maximum_allocation_mb: 4096
              yarn_scheduler_maximum_allocation_vcores: 4
          - type: NODEMANAGER
            config:
              yarn_nodemanager_resource_memory_mb: 4096
              yarn_nodemanager_resource_cpu_vcores: 4
              yarn_nodemanager_local_dirs: /tmp/nm
              yarn_nodemanager_log_dirs: /var/log/nm
          - type: GATEWAY
            config:
              mapred_submit_replication: 3
              mapred_reduce_tasks: 6
    host_templates:
      - name: Master1
        role_groups:
          - service: HDFS
            type: NAMENODE
          - service: HDFS
            type: SECONDARYNAMENODE
          - service: YARN
            type: RESOURCEMANAGER
          - service: YARN
            type: JOBHISTORY
      - name: Worker
        role_groups:
          - service: HDFS
            type: DATANODE
          - service: YARN
            type: NODEMANAGER
          - service: ZOOKEEPER
            type: SERVER
    parcels:
      CDH: "7.1.9-1.cdh7.1.9.p0.44702451"
    hosts:
      - name: master-01.cldr.internal
        host_template: Master1
      - name: worker-01.cldr.internal
        host_template: Worker
      - name: worker-02.cldr.internal
        host_template: Worker
      - name: worker-03.cldr.internal
        host_template: Worker

- name: Create a cluster from a cluster template
  cloudera.cluster.cluster:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: "7180"
    name: example-cluster
    template: "./files/cluster-template.json"
    add_repositories: yes

- name: Create an ECS cluster
  cloudera.cluster.cluster:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: 7180
    cluster_name: ECS-cluster
    cluster_version: "1.5.1-b626.p0.42068229"
    cluster_type: EXPERIENCE_CLUSTER
    state: present
    parcels:
      ECS: "1.5.1-b626.p0.42068229"
    services:
      - name: docker
        type: DOCKER
        config:
          docker_images_destination_registry_user: registry-user
          defaultDataPath: /mnt/docker
      - name: ecs
        type: ECS
        config:
          app_domain: test.lab.example
          k8s_webui_secret_admin_token: ecs-k8s_webui_secret_admin_token
          cp_prometheus_ingress_user: cloudera-manager
          infra_prometheus_ingress_user: cloudera-manager
          longhorn_replication: 2
          lsoDataPath: /ecs/local
          docker: docker
          cp_prometheus_ingress_password: password1
          infra_prometheus_ingress_password: password1
          defaultDataPath: /ecs/longhorn-storage
          nfs_over_provisioning: 800
    host_templates:
      - name: ecs_master
        role_groups:
          - service_type: DOCKER
            type: DOCKER_SERVER
          - service_type: ECS
            type: ECS_SERVER
      - name: ecs_workers
        role_groups:
          - service_type: DOCKER
            type: DOCKER_SERVER
          - service_type: ECS
            type: ECS_AGENT
    hosts:
      - name: ecs-master-01.test.lab.example
        host_template: ecs_master
      - name: ecs-worker-01.test.lab.example
        host_template: ecs_workers
      - name: ecs-worker-02.test.lab.example
        host_template: ecs_workers
      - name: ecs-worker-03.test.lab.example
        host_template: ecs_workers
    control_plane:
      datalake_cluster_name: PVC-Base
      remote_repo_url: "https://test_website/cdp-pvc-ds/1.5.1"
      control_plane_config:
        ContainerInfo:
               Mode: public
               CopyDocker: false
        Database:
          Mode: embedded
          EmbeddedDbStorage: 50
        Services:
          thunderheadenvironment:
            Config:
              database:
                name: db-env
          mlxcontrolplaneapp:
            Config:
              database:
                name: db-mlx
          dwx:
            Config:
              database:
                name: db-dwx
          cpxliftie:
            Config:
              database:
                name: db-liftie
          dex:
            Config:
              database:
                name: db-dex
          resourcepoolmanager:
            Config:
              database:
                name: db-resourcepoolmanager
          cdpcadence:
            Config:
              database:
                name: db-cadence
          cdpcadencevisibility:
            Config:
              database:
                name: db-cadence-visibility
          clusteraccessmanager:
            Config:
              database:
                name: db-clusteraccessmanager
          monitoringapp:
            Config:
              database:
                name: db-alerts
          thunderheadusermanagementprivate:
            Config:
              database:
                name: db-ums
          classicclusters:
            Config:
              database:
                name: cm-registration
          clusterproxy:
            Config:
              database:
                name: cluster-proxy
          dssapp:
            Config:
              database:
                name: db-dss-app
        Vault:
          Mode: embedded
"""

RETURN = r"""
cloudera_manager:
    description: Details about Cloudera Manager Cluster
    type: dict
    contains:
        name:
            description: The name of the cluster.
            type: str
            returned: always
        display_name:
            description: The name of the cluster displayed in the Cloudera Manager UI.
            type: str
            returned: always
        entity_status:
            description: Health status of the cluster.
            type: str
            returned: always
        version:
            description: Version of the cluster installed.
            type: str
            returned: always
        maintenance_mode:
            description: Maintance mode of cluster.
            type: bool
            returned: always
        maintenance_owners:
            description: List of maintance owners for cluster.
            type: list
            returned: always
        cluster_type:
            description: The type of cluster.
            type: str
            returned: always
        tags:
            description: List of tags for cluster.
            type: list
            returned: always
        uuid:
            description: The unique ID of the cluster.
            type: bool
            returned: always
"""

import json, yaml

from ansible.module_utils.common.text.converters import to_text, to_native

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    wait_command,
    ClouderaManagerModule,
    ClusterTemplate,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.parcel_utils import (
    Parcel,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.cluster_utils import (
    parse_cluster_result,
)

from cm_client import (
    ApiCluster,
    ApiClusterList,
    ApiClusterTemplate,
    ApiConfig,
    ApiConfigList,
    ApiDataContext,
    ApiHostRef,
    ApiHostRefList,
    ApiHostTemplate,
    ApiHostTemplateList,
    ApiRole,
    ApiRoleList,
    ApiRoleConfigGroup,
    ApiRoleConfigGroupRef,
    ApiRoleNameList,
    ApiService,
    ApiServiceConfig,
    ClouderaManagerResourceApi,
    ClustersResourceApi,
    HostsResourceApi,
    HostTemplatesResourceApi,
    ParcelResourceApi,
    ServicesResourceApi,
    RoleConfigGroupsResourceApi,
    RolesResourceApi,
    ControlPlanesResourceApi,
    ApiInstallEmbeddedControlPlaneArgs,
)
from cm_client.rest import ApiException


class ClouderaCluster(ClouderaManagerModule):
    def __init__(self, module):
        super(ClouderaCluster, self).__init__(module)

        self.name = self.get_param("name")
        self.cluster_version = self.get_param("cluster_version")
        self.type = self.get_param("type")
        self.state = self.get_param("state")
        self.template = self.get_param("template")
        self.add_repositories = self.get_param("add_repositories")
        self.maintenance = self.get_param("maintenance")
        self.hosts = self.get_param("hosts")
        self.host_templates = self.get_param("host_templates")
        self.services = self.get_param("services")
        self.parcels = self.get_param("parcels")
        self.tags = self.get_param("tags")
        self.display_name = self.get_param("display_name")
        self.contexts = self.get_param("contexts")
        self.auto_assign = self.get_param("auto_assign")
        self.control_plane = self.get_param("control_plane")
        self.auto_tls = self.get_param("auto_tls")
        self.force = self.get_param("force")

        self.changed = False
        self.output = {}

        self.delay = 15  # TODO Parameterize
        self.timeout = 7200  # TODO Parameterize
        self.message = "Ansible-powered"  # TODO Parameterize

        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        self.cm_api = ClouderaManagerResourceApi(self.api_client)
        self.cluster_api = ClustersResourceApi(self.api_client)
        self.service_api = ServicesResourceApi(self.api_client)
        self.host_template_api = HostTemplatesResourceApi(self.api_client)
        self.host_api = HostsResourceApi(self.api_client)
        self.role_group_api = RoleConfigGroupsResourceApi(self.api_client)
        self.role_api = RolesResourceApi(self.api_client)
        self.control_plane_api = ControlPlanesResourceApi(self.api_client)

        refresh = True

        # TODO manage services following the ClusterTemplateService data model
        # TODO manage host and host template assignments following the ClusterTemplateHostInfo data model
        # TODO manage host templates following the ClusterTemplateHostTemplate data model
        # TODO manage role config groups following the ClusterTemplateRoleConfigGroupInfo data model (-CREATE-, MODIFY)
        # TODO cluster template change management
        # TODO auto assign roles (xCREATEx, MODIFY)
        # TODO auto configure services and roles
        # TODO auto-TLS (separate module for full credential lifecycle)
        # TODO configure KRB (separate module for full KRB lifecycle)
        # TODO deploy client configs (services)
        # TODO auto-upgrade (bool: False) including prechecks
        # TODO refresh configurations (bool: True, set False to suppress restarts)
        # TODO restart arguments (selective restarts)
        # TODO rolling restart arguments
        # TODO rolling upgrade arguments

        # Retrieve existing cluster
        existing = None
        try:
            existing = self.cluster_api.read_cluster(cluster_name=self.name)
        except ApiException as ex:
            if ex.status != 404:
                raise ex

        # Prepare any cluster template content
        template_contents = None
        if self.template:
            try:
                with open(self.template, "r", encoding="utf-8") as file:
                    template_contents = json.load(file)
            except OSError as oe:
                self.module.fail_json(
                    msg=f"Error reading cluster template file, '{to_text(self.template)}'",
                    err=to_native(oe),
                )

        if self.state == "present":
            # Modify cluster
            if existing:
                self.module.warn(
                    "Module currently does not support reconcilation of cluster templates with existing clusters."
                )
                refresh = False

                # Reconcile the existing vs. the incoming values into a set of diffs
                # then process via the PUT /clusters/{clusterName} endpoint

                if self.auto_assign:
                    self.changed = True
                    if not self.module.check_mode:
                        self.cluster_api.auto_assign_roles(cluster_name=self.name)
                        refresh = True

            # Create cluster
            else:
                # TODO import_cluster_template appears to construct and first run the cluster, which is NOT what present should do
                # That would mean import_cluster_template should only be executed on a fresh cluster with 'started' or 'restarted' states
                if template_contents:
                    self.create_cluster_from_template(template_contents)
                else:
                    self.create_cluster_from_parameters()

            # Toggle AutoTLS
            if self.auto_tls is not None:
                if self.auto_tls:
                    enable_tls_cmd = (
                        self.cluster_api.configure_auto_tls_services_command(
                            cluster_name=self.name
                        )
                    )
                    wait_command(
                        api_client=self.api_client,
                        command=enable_tls_cmd,
                    )
                else:
                    disable_tls_cmd = self.cluster_api.disable_tls(
                        cluster_name=self.name,
                    )
                    wait_command(api_client=self.api_client, command=disable_tls_cmd)
        elif self.state == "absent":
            # Delete cluster
            refresh = False
            if existing:
                self.changed = True
                if not self.module.check_mode:
                    if existing.entity_status != "STOPPED":
                        stop = self.cluster_api.stop_command(cluster_name=self.name)
                        self.wait_command(stop, polling=self.timeout, delay=self.delay)

                    delete = self.cluster_api.delete_cluster(cluster_name=self.name)
                    self.wait_command(delete, polling=self.timeout, delay=self.delay)

        elif self.state == "started":
            # Already started
            if existing and existing.entity_status == "GOOD_HEALTH":
                refresh = False
                pass
            # Start underway
            elif existing and existing.entity_status == "STARTING":
                self.wait_for_active_cmd(self.name)
            # Needs starting
            else:
                # Create if needed
                if not existing:
                    if template_contents:
                        self.create_cluster_from_template(template_contents)
                    else:
                        self.create_cluster_from_parameters()

                # Toggle AutoTLS
                if self.auto_tls is not None:
                    if self.auto_tls:
                        enable_tls_cmd = (
                            self.cluster_api.configure_auto_tls_services_command(
                                cluster_name=self.name
                            )
                        )
                        wait_command(
                            api_client=self.api_client,
                            command=enable_tls_cmd,
                        )
                    else:
                        disable_tls_cmd = self.cluster_api.disable_tls(
                            cluster_name=self.name,
                        )
                        wait_command(
                            api_client=self.api_client, command=disable_tls_cmd
                        )

                self.changed = True
                if not self.module.check_mode:
                    # If newly created or created by not yet initialize
                    if not existing or existing.entity_status == "NONE" or self.force:
                        first_run = self.cluster_api.first_run(cluster_name=self.name)
                        self.wait_command(
                            first_run, polling=self.timeout, delay=self.delay
                        )
                    # Start the existing and previously initialized cluster
                    else:
                        start = self.cluster_api.start_command(cluster_name=self.name)
                        self.wait_command(start, polling=self.timeout, delay=self.delay)

        if self.state == "stopped":
            # Already stopped
            if existing and existing.entity_status == "STOPPED":
                refresh = False
                pass
            # Stop underway
            elif existing and existing.entity_status == "STOPPING":
                self.wait_for_active_cmd(self.name)
            # Needs stopping
            else:
                # Create if needed
                if not existing:
                    if template_contents:
                        self.create_cluster_from_template(template_contents)
                    else:
                        self.create_cluster_from_parameters()

                    # Toggle AutoTLS
                    if self.auto_tls is not None:
                        if self.auto_tls:
                            enable_tls_cmd = (
                                self.cluster_api.configure_auto_tls_services_command(
                                    cluster_name=self.name
                                )
                            )
                            wait_command(
                                api_client=self.api_client,
                                command=enable_tls_cmd,
                            )
                        else:
                            disable_tls_cmd = self.cluster_api.disable_tls(
                                cluster_name=self.name,
                            )
                            wait_command(
                                api_client=self.api_client, command=disable_tls_cmd
                            )
                # Stop an existing cluster
                else:
                    self.changed = True
                    # Toggle AutoTLS
                    if self.auto_tls is not None:
                        if self.auto_tls:
                            enable_tls_cmd = (
                                self.cluster_api.configure_auto_tls_services_command(
                                    cluster_name=self.name
                                )
                            )
                            wait_command(
                                api_client=self.api_client,
                                command=enable_tls_cmd,
                            )
                        else:
                            disable_tls_cmd = self.cluster_api.disable_tls(
                                cluster_name=self.name,
                            )
                            wait_command(
                                api_client=self.api_client, command=disable_tls_cmd
                            )
                    if not self.module.check_mode:
                        stop = self.cluster_api.stop_command(cluster_name=self.name)
                        self.wait_command(stop, polling=self.timeout, delay=self.delay)

        if self.state == "restarted":
            # Start underway
            if existing and existing.entity_status == "STARTING":
                self.wait_for_active_cmd(self.name)
            # Needs restarting
            else:
                # Create if needed
                if not existing:
                    if template_contents:
                        self.create_cluster_from_template(template_contents)
                    else:
                        self.create_cluster_from_parameters()

                # Toggle AutoTLS
                if self.auto_tls is not None:
                    if self.auto_tls:
                        enable_tls_cmd = (
                            self.cluster_api.configure_auto_tls_services_command(
                                cluster_name=self.name
                            )
                        )
                        wait_command(
                            api_client=self.api_client,
                            command=enable_tls_cmd,
                        )
                    else:
                        disable_tls_cmd = self.cluster_api.disable_tls(
                            cluster_name=self.name,
                        )
                        wait_command(
                            api_client=self.api_client, command=disable_tls_cmd
                        )

                self.changed = True
                if not self.module.check_mode:
                    if self.force:
                        first_run = self.cluster_api.first_run(cluster_name=self.name)
                        self.wait_command(
                            first_run, polling=self.timeout, delay=self.delay
                        )
                    restart = self.cluster_api.restart_command(cluster_name=self.name)
                    self.wait_command(restart, polling=self.timeout, delay=self.delay)

        if refresh:
            # Retrieve the updated cluster details
            self.output = parse_cluster_result(
                self.cluster_api.read_cluster(cluster_name=self.name)
            )
        elif existing:
            self.output = parse_cluster_result(existing)

    def wait_for_composite_cmd(self, command_id: str):
        cmd = self.wait_for_command_state(
            command_id=command_id,
            polling_interval=self.delay,
        )
        if not cmd[0].success:
            collected_msgs = [
                f"[{c.name}] {c.result_message}"
                for c in cmd[0].children.items
                if not c.success
            ]
            self.module.fail_json(msg="\n".join(collected_msgs))
        elif not cmd:
            self.module.fail_json(msg="Invalid command result", cmd=to_native(cmd))

        return cmd

    def wait_for_active_cmd(self, cluster_name: str):
        active_cmd = None
        try:
            active_cmd = next(
                iter(
                    self.cluster_api.list_active_commands(
                        cluster_name=cluster_name
                    ).items
                ),
                None,
            )
        except ApiException as e:
            if e.status != 404:
                raise e

        if active_cmd:
            self.wait_for_command_state(
                command_id=active_cmd.id,
                polling_interval=self.delay,
            )

    def create_cluster_from_template(self, template_contents: dict):
        payload = dict()

        # Construct import template payload from the template and/or explicit parameters
        explicit_params = dict()

        # Set up 'instantiator' parameters
        explicit_params.update(instantiator=dict(clusterName=self.name))

        # Merge/overlay any explicit parameters over the template
        TEMPLATE = ClusterTemplate(
            warn_fn=self.module.warn, error_fn=self.module.fail_json
        )
        TEMPLATE.merge(template_contents, explicit_params)
        payload.update(body=template_contents)

        # Update to include repositories
        if self.add_repositories:
            payload.update(add_repositories=True)

        # Execute the import
        self.changed = True
        if not self.module.check_mode:
            import_template_request = self.cm_api.import_cluster_template(
                **payload
            ).to_dict()

            command_id = import_template_request["id"]
            self.wait_for_command_state(
                command_id=command_id, polling_interval=self.delay
            )

    def create_cluster_from_parameters(self):
        if self.cluster_version is None:
            self.module.fail_json(
                msg=f"Cluster must be created. Missing required parameter: cluster_version"
            )

        # Configure the core cluster
        cluster = ApiCluster(
            name=self.name,
            full_version=self.cluster_version,
            cluster_type=self.type,
        )

        # Configure cluster services
        if self.services:
            cluster.services = [self.marshal_service(s) for s in self.services]

        # Configure cluster contexts
        if self.contexts:
            cluster.data_context_refs = [ApiDataContext(name=d) for d in self.contexts]

        # Execute the creation
        self.changed = True

        if not self.module.check_mode:
            # Validate any incoming host membership to fail fast
            if self.hosts:
                hostrefs = self.marshal_hostrefs({h["name"]: h for h in self.hosts})
                hostref_by_host_id = {h.host_id: h for h in hostrefs}
                hostref_by_hostname = {h.hostname: h for h in hostrefs}

            # Create the cluster configuration
            self.cluster_api.create_clusters(body=ApiClusterList(items=[cluster]))
            self.wait_for_active_cmd(self.name)

            # Add host templates to cluster
            if self.host_templates:

                # Prepare host template role group assignments
                # and discover base role groups if needed
                templates = [
                    ApiHostTemplate(
                        name=ht["name"],
                        role_config_group_refs=[
                            ApiRoleConfigGroupRef(
                                rcg["name"]
                                if rcg["name"]
                                else self.find_base_role_group_name(
                                    service_name=rcg["service"],
                                    service_type=rcg["service_type"],
                                    role_type=rcg["type"],
                                )
                            )
                            for rcg in ht["role_groups"]
                        ],
                    )
                    for ht in self.host_templates
                ]
                self.host_template_api.create_host_templates(
                    cluster_name=self.name,
                    body=ApiHostTemplateList(items=templates),
                )

            # Add hosts to cluster and set up assignments
            template_map = {}
            role_group_list = []
            role_list = []

            if self.hosts:
                # Add the hosts
                self.cluster_api.add_hosts(
                    cluster_name=self.name,
                    body=ApiHostRefList(items=hostrefs),
                )

                for h in self.hosts:
                    # Normalize hostref
                    hostref = (
                        hostref_by_host_id[h["name"]]
                        if h["name"] in hostref_by_host_id
                        else hostref_by_hostname[h["name"]]
                    )

                    # Prepare host template assignments
                    if h["host_template"]:
                        if h["host_template"] in template_map:
                            template_map[h["host_template"]].append(hostref)
                        else:
                            template_map[h["host_template"]] = [hostref]

                    # Prepare role group assignments
                    if h["role_groups"]:
                        role_group_list.append((hostref, h["role_groups"]))

                    # Prepare role overrides
                    if h["roles"]:
                        role_list.append((hostref, h["roles"]))

            # Activate parcels
            if self.parcels:
                parcel_api = ParcelResourceApi(self.api_client)
                try:
                    for p, v in self.parcels.items():
                        parcel = Parcel(
                            parcel_api=parcel_api,
                            product=p,
                            version=v,
                            cluster=self.name,
                            log=self.module.log,
                            delay=self.delay,
                            timeout=self.timeout,
                        )
                        if self.hosts:
                            parcel.activate()
                        else:
                            parcel.download()
                except ApiException as ae:
                    self.module.fail_json(
                        msg="Error managing parcel states: " + to_native(ae)
                    )

            # Apply host templates
            for ht, refs in template_map.items():
                self.host_template_api.apply_host_template(
                    cluster_name=self.name,
                    host_template_name=ht,
                    start_roles=False,
                    body=ApiHostRefList(items=refs),
                )

            # Configure direct role group assignments
            if role_group_list:
                # Gather all the RCGs for all services, as the host template might
                # not reference RCGs that are directly configured in the service
                # definition, i.e. base role groups
                all_rcgs = {
                    rcg.name: (
                        rcg.base,
                        s.name,
                        rcg.role_type,
                    )
                    for s in self.service_api.read_services(
                        cluster_name=self.name
                    ).items  # s.name
                    for rcg in self.role_group_api.read_role_config_groups(
                        cluster_name=self.name, service_name=s.name
                    ).items
                }

                for hostref, host_rcgs in role_group_list:
                    for rcg in host_rcgs:
                        rcg_ref = None

                        if rcg["name"]:
                            # Use the declared RCG name
                            if rcg["name"] not in all_rcgs:
                                self.module.fail_json(
                                    msg="Role config group '%s' not found on cluster."
                                    % rcg["name"]
                                )
                            else:
                                rcg_ref = all_rcgs[rcg["name"]]
                        else:
                            # Or discover the role group
                            rcg_name = next(
                                iter(
                                    [
                                        name
                                        for name, refs in all_rcgs.items()
                                        if refs[0]
                                        and refs[1] == rcg["service"]
                                        and refs[2] == rcg["type"]
                                    ]
                                ),
                                None,
                            )

                            if rcg_name is None:
                                self.module.fail_json(
                                    msg="Unable to find base role group, '%s [%s]', on cluster, '%s'"
                                    % (rcg["service"], rcg["type"], self.name)
                                )

                            rcg_ref = all_rcgs[rcg_name]

                        # Add the role of that type to the host (generating a name)
                        direct_roles = self.role_api.create_roles(
                            cluster_name=self.name,
                            service_name=rcg_ref[1],
                            body=ApiRoleList(
                                items=[ApiRole(type=rcg_ref[2], host_ref=hostref)]
                            ),
                        )

                        # Move the newly-created role to the RCG if it is not a base/default group
                        if not rcg_ref[0]:
                            self.role_group_api.move_roles(
                                cluster_name=self.name,
                                role_config_group_name=rcg["name"],
                                service_name=rcg_ref[1],
                                body=ApiRoleNameList(
                                    items=[direct_roles.items[0].name]
                                ),
                            )

            # Configure per-host role overrides
            for (
                hostref,
                overrides,
            ) in role_list:
                for override in overrides:
                    # Discover the role on the host
                    host_role = next(
                        iter(
                            self.role_api.read_roles(
                                cluster_name=self.name,
                                service_name=override["service"],
                                filter="type==%s;hostId==%s"
                                % (override["type"], hostref.host_id),
                            ).items
                        ),
                        None,
                    )

                    if host_role is not None:
                        self.role_api.update_role_config(
                            cluster_name=self.name,
                            service_name=override["service"],
                            role_name=host_role.name,
                            message=self.message,
                            body=ApiConfigList(
                                items=[
                                    ApiConfig(name=k, value=v)
                                    for k, v in override["config"].items()
                                ]
                            ),
                        )
                    else:
                        self.module.fail_json(
                            msg="Role not found. No role type '%s' for service '%s' found on host '%s'"
                            % (override["type"], override["service"], hostref.hostname)
                        )
            # Configure the experience cluster
            if self.control_plane:
                values_yaml_data = self.control_plane["control_plane_config"]
                values_yaml_str = yaml.dump(values_yaml_data)

                # Assemble body for Install Control Plane request
                body = ApiInstallEmbeddedControlPlaneArgs(
                    experience_cluster_name=self.name,
                    containerized_cluster_name=self.name,
                    datalake_cluster_name=self.control_plane["datalake_cluster_name"],
                    remote_repo_url=self.control_plane["remote_repo_url"],
                    values_yaml=values_yaml_str,
                )
                setup_control_plane = (
                    self.control_plane_api.install_embedded_control_plane(body=body)
                )
                self.wait_for_command_state(
                    command_id=setup_control_plane.id, polling_interval=self.delay
                )

            # Execute auto-role assignments
            if self.auto_assign:
                self.cluster_api.auto_assign_roles(cluster_name=self.name)

    def marshal_service(self, options: dict) -> ApiService:
        service = ApiService(name=options["name"], type=options["type"])

        if options["display_name"]:
            service.display_name = options["display_name"]

        # Service-wide configuration
        if options["config"]:
            service.config = ApiServiceConfig(
                items=[ApiConfig(name=k, value=v) for k, v in options["config"].items()]
            )

        if options["role_groups"]:
            rcg_list = []

            for body in options["role_groups"]:
                rcg = ApiRoleConfigGroup(role_type=body["type"])

                # Either a defined role group or a default/base group
                if body["name"]:
                    rcg.name = body["name"]
                else:
                    rcg.base = True

                if body["display_name"]:
                    rcg.display_name = body["display_name"]

                if body["config"]:
                    rcg.config = ApiConfigList(
                        items=[
                            ApiConfig(name=k, value=v)
                            for k, v in body["config"].items()
                        ]
                    )

                rcg_list.append(rcg)

            service.role_config_groups = rcg_list

        if "tags" in options:
            pass

        if "version" in options:
            pass

        return service

    def marshal_hostrefs(self, hosts: dict) -> list[ApiHostRef]:
        results = []
        hosts_query = self.host_api.read_hosts().items
        for h in hosts_query:
            if h.host_id in hosts.keys() or h.hostname in hosts.keys():
                if (
                    h.cluster_ref is not None
                    and h.cluster_ref.cluster_name != self.name
                ):
                    self.module.fail_json(
                        msg=f"Invalid host reference! Host {h.hostname} ({h.host_id}) already in use with cluster '{h.cluster_ref.cluster_name}'!"
                    )
                results.append(ApiHostRef(host_id=h.host_id, hostname=h.hostname))
        if len(results) != len(hosts.keys()):
            self.module.fail_json(
                msg="Did not find the following hosts: "
                + ", ".join(set(hosts.keys() - set(results)))
            )
        return results

    def find_base_role_group_name(
        self, role_type: str, service_name: str = None, service_type: str = None
    ) -> str:
        if service_name:

            rcgs = [
                rcg
                for s in self.service_api.read_services(cluster_name=self.name).items
                for rcg in self.role_group_api.read_role_config_groups(
                    cluster_name=self.name, service_name=s.name
                ).items
                if s.name == service_name
            ]
        elif service_type:
            rcgs = [
                rcg
                for s in self.service_api.read_services(cluster_name=self.name).items
                for rcg in self.role_group_api.read_role_config_groups(
                    cluster_name=self.name, service_name=s.name
                ).items
                if s.type == service_type
            ]

        base = next(
            iter([rcg for rcg in rcgs if rcg.base and rcg.role_type == role_type]),
            None,
        )

        if base is None:
            self.module.fail_json(
                "Invalid role group; unable to discover base role group for service role, %s"
                % role_type
            )
        else:
            return base.name


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            name=dict(required=True, aliases=["cluster_name"]),
            cluster_version=dict(),
            type=dict(
                aliases=["cluster_type"],
                choices=["BASE_CLUSTER", "COMPUTE_CLUSTER", "EXPERIENCE_CLUSTER"],
            ),
            state=dict(
                default="present",
                choices=["present", "absent", "stopped", "started", "restarted"],
            ),
            # A cluster template used as the "baseline" for the parameters
            template=dict(type="path", aliases=["cluster_template"]),
            # Only valid if using 'template'
            add_repositories=dict(type="bool", default=False),
            # Flag for warning suppression
            maintenance=dict(type="bool", aliases=["maintenance_enabled"]),
            # Services, service configs, role config groups
            services=dict(
                type="list",
                elements="dict",
                options=dict(
                    name=dict(aliases=["ref", "ref_name"]),
                    type=dict(required=True),
                    version=dict(),
                    # Service-level config
                    config=dict(type="dict"),
                    # Role config groups (RCG)
                    role_groups=dict(
                        type="list",
                        elements="dict",
                        options=dict(
                            name=dict(aliases=["ref", "ref_name"]),
                            type=dict(required=True, aliases=["role_type"]),
                            display_name=dict(),
                            config=dict(type="dict"),
                        ),
                        aliases=["role_config_groups"],
                    ),
                    display_name=dict(),
                    tags=dict(type="dict"),
                ),
            ),
            # Hosts, host template assignments, explicit role group assignments, and per-host role overrides
            hosts=dict(
                type="list",
                elements="dict",
                options=dict(
                    name=dict(required=True, aliases=["host_id", "hostname"]),
                    config=dict(),
                    host_template=dict(),
                    role_groups=dict(
                        type="list",
                        elements="dict",
                        options=dict(
                            name=dict(aliases=["ref", "ref_name"]),
                            service=dict(
                                required=True, aliases=["service_name", "service_ref"]
                            ),
                            type=dict(aliases=["role_type"]),
                        ),
                        aliases=["role_config_groups"],
                        mutually_exclusive=[
                            ("name", "type"),
                        ],
                        required_one_of=[
                            ("name", "type"),
                        ],
                    ),
                    roles=dict(
                        type="list",
                        elements="dict",
                        options=dict(
                            service=dict(
                                required=True, aliases=["service_name", "service_ref"]
                            ),
                            type=dict(required=True, aliases=["role_type"]),
                            config=dict(type="dict", required=True),
                        ),
                    ),
                    tags=dict(),
                ),
            ),
            # Host templates
            host_templates=dict(
                type="list",
                elements="dict",
                options=dict(
                    name=dict(required=True),
                    role_groups=dict(
                        type="list",
                        elements="dict",
                        required=True,
                        options=dict(
                            name=dict(aliases=["ref", "ref_name"]),
                            service=dict(aliases=["service_name", "service_ref"]),
                            type=dict(aliases=["role_type"]),
                            service_type=dict(),
                        ),
                        aliases=["role_config_groups"],
                        mutually_exclusive=[
                            ("service", "service_type"),
                        ],
                        requires_one_of=[
                            ("service", "service_type"),
                        ],
                    ),
                ),
            ),
            control_plane=dict(
                type="dict",
                options=dict(
                    remote_repo_url=dict(required=True, type="str"),
                    datalake_cluster_name=dict(required=True, type="str"),
                    control_plane_config=dict(
                        required=True, type="dict", aliases=["values_yaml"]
                    ),
                ),
            ),
            # Parcels is a dict of product:version of the cluster
            parcels=dict(type="dict", aliases=["products"]),
            # Tags is a dict of key:value assigned to the cluster
            tags=dict(),
            # Optional UI name
            display_name=dict(),
            # Optional data contexts, required for compute-type clusters
            contexts=dict(type="list", elements="str", aliases=["data_contexts"]),
            # Optional enable/disable TLS for the cluster
            auto_tls=dict(type="bool", aliases=["tls_enabled", "cluster_tls"]),
            # Optional force first run services initialization
            force=dict(type="bool", aliases=["forced_init"]),
            # Optional auto-assign roles on cluster (honors existing assignments)
            auto_assign=dict(type="bool", default=False, aliases=["auto_assign_roles"]),
        ),
        supports_check_mode=True,
        mutually_exclusive=[
            ("cdh_version", "cdh_short_version"),
        ],
        required_if=[("type", "COMPUTE_CLUSTER", ("contexts"))],
    )

    result = ClouderaCluster(module)

    changed = result.changed

    output = dict(
        changed=changed,
        cloudera_manager=result.output,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
