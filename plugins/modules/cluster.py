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

import json

from ansible.module_utils.common.text.converters import to_text, to_native

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
    ClusterTemplate,
)

from cm_client import (
    ApiCluster,
    ApiClusterList,
    ApiClusterTemplate,
    ApiConfig,
    ApiConfigList,
    ApiDataContext,
    ApiDataContextList,
    ApiHostRef,
    ApiHostRefList,
    ApiRoleConfigGroup,
    ApiRoleConfigGroupList,
    ApiRoleTypeConfig,
    ApiService,
    ApiServiceConfig,
    ClouderaManagerResourceApi,
    ClustersResourceApi,
    HostsResourceApi,
)
from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: cluster
short_description: Manage the lifecycle and state of a cluster
description:
  - Enables cluster management, cluster creation, deletion, and unified control of all services of a cluster.
  - Create or delete cluster in Cloudera Manager.
  - Start or stop all services inside the cluster.
  - If provided the C(template) parameter, the module will create a cluster based on the template.
author:
  - "Ronald Suplina (@rsuplina)"
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
"""

EXAMPLES = r"""
---
- name: Create an ECS cluster
  cloudera.cluster.cluster:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: 7180
    clusterName: example-cluster
    cluster_version: "1.5.1-b626.p0.42068229"
    cluster_type: EXPERIENCE_CLUSTER
    state: present
   
- name: Create a cluster from a cluster template
  cloudera.cluster.cm_cluster:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    port: "7180"
    clusterName: example-cluster
    template: "./files/cluster-template.json"
    add_repositories: yes

- name: Start all services on a cluster
  cloudera.cluster.cluster:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    clusterName: example-cluster
    state: started

- name: Delete a Cluster
  cloudera.cluster.cm_cluster:
    host: example.cloudera.com
    port: "7180"
    username: "jane_smith"
    password: "S&peR4Ec*re"
    clusterName: example-cluster
    state: absent
"""

RETURN = r"""
---
cloudera_manager:
    description: Details about Cloudera Manager Cluster
    type: dict
    contains:
        cluster_type:
            description: The type of cluster created from template.
            type: str
            returned: optional
        cluster_url:
            description: Url of Cloudera Manager cluster.
            type: str
            returned: optional
        display_name:
            description: The name of the cluster displayed on the site.
            type: str
            returned: optional
        entity_status:
            description: Health status of the cluster.
            type: str
            returned: optional
        full_version:
            description: Version of the cluster installed.
            type: str
            returned: optional
        hosts_url:
            description: Url of all the hosts on which cluster is installed.
            type: str
            returned: optional
        maintenance_mode:
            description: Maintance mode of Cloudera Manager Cluster.
            type: bool
            returned: optional
        maintenance_owners:
            description: List of Maintance owners for Cloudera Manager Cluster.
            type: list
            returned: optional
        name:
            description: The name of the cluster created.
            type: str
            returned: optional
        tags:
            description: List of tags for Cloudera Manager Cluster.
            type: list
            returned: optional
        uuid:
            description: Unique ID of created cluster
            type: bool
            returned: optional
"""


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
        self.services = self.get_param("services")
        self.parcels = self.get_param("parcels")
        self.tags = self.get_param("tags")
        self.display_name = self.get_param("display_name")
        self.contexts = self.get_param("contexts")
        self.auto_assign = self.get_param("auto_assign")

        self.changed = False
        self.output = {}

        self.polling_interval = 30

        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        self.cm_api = ClouderaManagerResourceApi(self.api_client)
        self.cluster_api = ClustersResourceApi(self.api_client)
        self.host_api = HostsResourceApi(self.api_client)

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
        # TODO cluster object return

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

        elif self.state == "absent":
            # Delete cluster

            refresh = False

            # TODO Check for status when deleting
            # if existing and existing.entity_status == "":
            #     self.wait_for_active_cmd(cluster_api, self.cluster_name)
            # elif existing:
            if existing:
                self.changed = True
                if not self.module.check_mode:
                    self.cluster_api.delete_cluster(cluster_name=self.name)
                    self.wait_for_active_cmd(self.name)

        elif self.state == "started":
            # TODO NONE seems to be fresh cluster, never run before
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

                self.changed = True
                if not self.module.check_mode:
                    # If newly created or created by not yet initialize
                    if not existing or existing.entity_status == "NONE":
                        first_run = self.cluster_api.first_run(cluster_name=self.name)
                        self.wait_for_composite_cmd(first_run.id)
                    # Start the existing and previously initialized cluster
                    else:
                        start = self.cluster_api.start_command(cluster_name=self.name)
                        self.wait_for_composite_cmd(start.id)

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
                # Stop an existing cluster
                else:
                    self.changed = True
                    if not self.module.check_mode:
                        stop = self.cluster_api.stop_command(cluster_name=self.name)
                        self.wait_for_composite_cmd(stop.id)

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

                self.changed = True
                if not self.module.check_mode:
                    restart = self.cluster_api.restart_command(cluster_name=self.name)
                    self.wait_for_composite_cmd(restart.id)

        if refresh:
            # Retrieve the updated cluster details
            self.output = self.cluster_api.read_cluster(
                cluster_name=self.name
            ).to_dict()
        elif existing:
            self.output = existing.to_dict()

    def wait_for_composite_cmd(self, command_id: str):
        cmd = self.wait_for_command_state(
            command_id=command_id,
            polling_interval=self.polling_interval,
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
                polling_interval=self.polling_interval,
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
        payload.update(body=ApiClusterTemplate(**template_contents))

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
                command_id=command_id, polling_interval=self.polling_interval
            )

    def create_cluster_from_parameters(self):
        if self.cluster_version is None:  # or self.type is None:
            self.module.fail_json(
                msg=f"Cluster must be created. Missing required parameter: cluster_version"
            )

        cluster = ApiCluster(
            name=self.name,
            full_version=self.cluster_version,
            cluster_type=self.type,
        )

        if self.services:
            cluster.services = [self.marshal_service(s) for s in self.services]

        if self.contexts:
            cluster.data_context_refs = [ApiDataContext(name=d) for d in self.contexts]

        # Execute the creation
        self.changed = True

        if not self.module.check_mode:
            # Validate any incoming host membership to fail fast
            if self.hosts:
                hostrefs = self.marshal_hostrefs(self.hosts)

            self.cluster_api.create_clusters(body=ApiClusterList(items=[cluster]))
            self.wait_for_active_cmd(self.name)

            if self.hosts:
                self.cluster_api.add_hosts(
                    cluster_name=self.name, body=ApiHostRefList(items=hostrefs)
                )

            if self.auto_assign:
                self.cluster_api.auto_assign_roles(cluster_name=self.name)

    def marshal_service(self, options: str) -> ApiService:
        # - name
        # - type
        # - config
        # roles
        # - displayName
        # roleConfigGroups
        # tags
        # serviceVersion

        service = ApiService(name=options["name"], type=options["type"])

        if "display_name" in options:
            service.display_name = options["display_name"]

        if "config" in options:
            service.config = ApiServiceConfig(
                items=[ApiConfig(name=k, value=v) for k, v in options["config"].items()]
            )

        # list[ApiRole]
        # name
        # type
        # hostRef
        # config
        # tags
        if "roles" in options:
            pass

        if "role_config_groups" in options:
            rcg_list = []

            for body in options["role_config_groups"]:
                rcg = ApiRoleConfigGroup(name=body["name"], role_type=body["type"])

                if "display_name" in body:
                    rcg.display_name = body["display_name"]

                if "base" in body:
                    rcg.base = body["base"]

                if "config" in body:
                    rcg.config = ApiConfigList(
                        items=[
                            ApiConfig(name=k, value=v)
                            for k, v in body["config"].items()
                        ]
                    )

                rcg_list.append(rcg)

            service.role_config_groups = rcg_list

        return service

    def marshal_hostrefs(self, hosts: dict):
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
            maintenance=dict(type="bool", aliases=["maintenance_enabled"]),
            # Services and configs; keys are refname
            services=dict(
                type="list",
                elements="dict",
                options=dict(
                    name=dict(required=True, aliases=["ref_name"]),
                    type=dict(required=True),
                    # Service-level config
                    config=dict(type="dict"),
                    # Role config groups (RCG)
                    role_config_groups=dict(
                        type="list",
                        options=dict(
                            name=dict(required=True, aliases=["ref_name"]),
                            type=dict(required=True, aliases=["role_type"]),
                            base=dict(type="bool"),  # Will ignore name if True
                            display_name=dict(),
                            config=dict(type="dict"),
                        ),
                    ),
                    # Roles: keys are refName, values are role type
                    roles=dict(type="dict"),
                    display_name=dict(),
                    tags=dict(type="dict"),
                ),
            ),
            # Hosts and host template assignments; keys are host_id or hostname
            hosts=dict(type="dict"),
            # Host templates
            host_templates=dict(),
            # Parcels is a dict of product:version of the cluster
            parcels=dict(type="dict", elements="str", aliases=["products"]),
            # Tags is a dict of key:value assigned to the cluster
            tags=dict(),
            # Optional UI name
            display_name=dict(),
            # Optional data contexts, required for compute-type clusters
            contexts=dict(type="list", elements="str", aliases=["data_contexts"]),
            # Optional enable/disable TLS for the cluster
            tls=dict(type="bool", aliases=["tls_enabled", "cluster_tls"]),
            # Optional auto-assign roles on cluster (honors existing assignments)
            auto_assign=dict(type="bool", default=False, aliases=["auto_assign_roles"]),
        ),
        supports_check_mode=True,
        # required_together=[
        #     ("cdh_version", "type"),
        # ],
        mutually_exclusive=[("cdh_version", "cdh_short_version")],
        required_if=[
            ("type", "COMPUTE_CLUSTER", ("contexts")),
        ],
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
