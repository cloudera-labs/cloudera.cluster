#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2025 Cloudera, Inc. All Rights Reserved.
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

import yaml
from cm_client import (
    ClustersResourceApi,
    ControlPlanesResourceApi,
    ApiInstallControlPlaneArgs,
    ApiInstallEmbeddedControlPlaneArgs,
    CommandsResourceApi,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)

from ansible_collections.cloudera.cluster.plugins.module_utils.cluster_utils import (
    parse_cluster_result,
    parse_control_plane_result,
)

from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
module: control_plane
short_description: Manage Cloudera control planes
description:
  - Manage the lifecycle and state of control planes in Cloudera on-premise deployments.
  - Install, uninstall, and manage both normal and K8s embedded control planes.
  - Check for existing control planes and handle idempotency.
author:
  - "Jim Enright (@jimright)"
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
attributes:
  check_mode:
    support: full
requirements:
  - cm-client
options:
  state:
    description:
      - The desired state of the control plane.
      - If I(state=present), the control plane will be installed if it does not exist.
      - If I(state=absent), the control plane will be uninstalled if it exists.
    type: str
    required: false
    default: present
    choices:
      - present
      - absent
  type:
    description:
      - The type of control plane to manage.
      - V(external) for external control plane installation.
      - V(embedded) for embedded control plane installation.
    type: str
    required: true
    choices:
      - external
      - embedded
  name:
    description:
      - The name of the Containerized Cluster that will bring up this control plane.
      - Required for embedded control planes.
    type: str
    required: false
    aliases:
      - containerized_cluster_name
      - control_plane_name
  datalake_cluster_name:
    description:
      - The name of the datalake cluster to use for the initial environment in this control plane.
      - Required when creating O(state=present) for embedded control plane O(type=embedded).
    type: str
    required: false
  namespace:
    description:
      - The namespace where the control plane should be installed.
      - Required for external control planes, O(type=external).
    type: str
    required: false
  selected_features:
    description:
      - The list of features to enable in the control plane.
      - Only used during creation O(state=present) of embedded control planes O(type=embedded).
    type: list
    elements: str
    required: false
  remote_repo_url:
    description:
      - The URL of the remote repository where the artifacts used to install the control plane are hosted.
      - Required when O(state=present)
    type: str
    required: false
  values_yaml:
    description:
      - The content of the values YAML used to configure the control plane.
      - Required when O(state=present).
    type: str
    required: false
    aliases:
      - control_plane_config
  kubernetes_type:
    description:
      - The Kubernetes type on which the control plane should run.
      - Required for external control planes, O(type=external).
    type: str
    required: false
  kubeconfig:
    description:
      - The content of the kubeconfig file of the kubernetes environment on which the install will be performed.
      - Required for external control planes, O(type=external).
    type: str
    required: false
  is_override_allowed:
    description:
      - Flag to specify if the control plane installation override existing configurations.
      - Only used during creation O(state=present) of external control planes O(type=external).
    type: bool
    required: false
seealso:
  - module: cloudera.cluster.control_plane_info
"""

EXAMPLES = r"""
- name: Install a external control plane
  cloudera.cluster.control_plane:
    host: "example.cloudera.host"
    username: "admin"
    password: "admin_password"
    state: present
    type: normal
    remote_repo_url: "https://archive.cloudera.com/cdp-pvc/7.1.9.0/"

- name: Install an embedded control plane
  cloudera.cluster.control_plane:
    host: "example.cloudera.host"
    username: "admin"
    password: "admin_password"
    state: present
    type: embedded
    namespace: "cdp-pvc"
    kubernetes_type: "EKS"
    remote_repo_url: "https://archive.cloudera.com/cdp-pvc/7.1.9.0/"

- name: Uninstall a control plane
  cloudera.cluster.control_plane:
    host: "example.cloudera.host"
    username: "admin"
    password: "admin_password"
    state: absent
"""

RETURN = r"""
control_plane:
  description: Information about the control plane after the operation.
  type: dict
  returned: always
  contains:
    namespace:
      description: The namespace where the control plane is installed.
      type: str
      returned: when available
    uuid:
      description: The universally unique ID of this control plane.
      type: str
      returned: when available
    remote_repo_url:
      description: The URL of the remote repository.
      type: str
      returned: when available
    version:
      description: The CDP version of the control plane.
      type: str
      returned: when available
    kubernetes_type:
      description: The Kubernetes type on which the control plane is running.
      type: str
      returned: when available
    tags:
      description: Tags associated with the control plane.
      type: list
      elements: dict
      returned: when available
msg:
  description: A message describing the result of the operation.
  type: str
  returned: always
"""


class ControlPlane(ClouderaManagerModule):
    def __init__(self, module):
        super(ControlPlane, self).__init__(module)

        self.state = self.get_param("state")
        self.type = self.get_param("type")
        self.remote_repo_url = self.get_param("remote_repo_url")
        self.values_yaml = self.get_param("values_yaml")

        # Embedded Control plane parameters
        self.name = self.get_param("name")
        self.datalake_cluster_name = self.get_param("datalake_cluster_name")
        self.selected_features = self.get_param("selected_features")

        # External Control plane parameters
        self.kubernetes_type = self.get_param("kubernetes_type")
        self.namespace = self.get_param("namespace")
        self.kubeconfig = self.get_param("kubeconfig")
        self.is_override_allowed = self.get_param("is_override_allowed")

        self.delay = (
            15  # Sleep time between wait for control plane install cmd to complete
        )

        # Initialize the output
        self.changed = False
        self.output = {}
        self.msg = ""

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        """Process the control plane management operation."""

        # Check parameters that are required depending on control plane type
        if self.type == "embedded" and self.state == "present":
            if any(
                param is None
                for param in [
                    self.name,
                    self.remote_repo_url,
                    self.datalake_cluster_name,
                ]
            ):
                self.module.fail_json(
                    msg="Parameter 'name', 'remote_repo_url' and 'datalake_cluster_name' are required when creating an embedded control plane.",
                )

        try:
            self.cp_api_instance = ControlPlanesResourceApi(self.api_client)
            current_cps = self.cp_api_instance.get_control_planes().items
            # current_cp_list = []

            # if current_cps and hasattr(current_cps, 'items'):
            # current_cp_list = current_cps.items
            # elif current_cps and isinstance(current_cps, list):
            #     current_cp_list = current_cps
            # elif current_cps:
            #     current_cp_list = [current_cps]

        except ApiException as e:
            if e.status == 404:
                current_cps = []
            else:
                raise e

        # Search for experience clusters matching the control plane name
        try:
            self.cluster_api_instance = ClustersResourceApi(self.api_client)

            if self.name:
                existing_experience_cluster = parse_cluster_result(
                    self.cluster_api_instance.read_cluster(cluster_name=self.name),
                )

        except ApiException as e:
            if e.status == 404:

                # TODO: For External control plane, check if Experience cluster needs to pre-exist
                self.module.fail_json(
                    msg=f"Failed to find Experience Cluster {self.name}. Cluster should exist before creating the control plane.",
                    details=str(e),
                )
            else:
                raise e

        # Find matching control plane
        existing_cp = self._find_matching_control_plane(
            current_cps, existing_experience_cluster,
        )

        if self.state == "present":
            if existing_cp:
                # Control plane already exists
                self.changed = False
                self.module.warn(
                    "Control plane matching the required parameters already exists. Reconciliation is not currently supported.",
                )
                self.output = parse_control_plane_result(existing_cp)
                self.msg = "Control plane matching the required parameters already exists. Reconciliation is not currently supported."
            else:
                # Install new control plane
                if not self.module.check_mode:
                    self._install_control_plane()
                self.changed = True

        elif self.state == "absent":
            if existing_cp:
                # Uninstall existing control plane
                if not self.module.check_mode:
                    self._uninstall_control_plane(existing_experience_cluster)
                self.changed = True
            else:
                # Control plane doesn't exist
                self.changed = False
                self.msg = "Control plane does not exist, nothing to uninstall"

    def _find_matching_control_plane(self, control_planes, experience_cluster):
        """Find a control plane that matches the target parameters."""
        if not control_planes:
            return None

        # Initialize match
        matches = True

        for cp in control_planes:
            cp_dict = cp.to_dict()

            if self.type == "embedded":

                # Extract the value of the _cldr_cm_ek8s_control_plane tag from the tags list
                # experience_cluster_uuid = experience_cluster.get('tags', []).tag.get('_cldr_cm_ek8s_control_plane')

                experience_cluster_uuid = experience_cluster.get("tags", {}).get(
                    "_cldr_cm_ek8s_control_plane",
                )

                # For embedded control planes, we need to check the control plane uuid
                # this is accessed via the cluster name in the experience cluster
                if (
                    experience_cluster_uuid
                    and cp_dict.get("uuid") != experience_cluster_uuid
                ):
                    matches = False

            if self.type == "external":
                # For external control planes, we need to check the namespace and kubernetes type

                if self.namespace and cp_dict.get("namespace") != self.namespace:
                    matches = False

                if (
                    self.kubernetes_type
                    and cp_dict.get("kubernetes_type") != self.kubernetes_type
                ):
                    matches = False

            if matches:
                return cp

        return None

    def _install_control_plane(self):
        """Install a control plane based on the type."""

        try:
            if self.type == "embedded":
                # Install embedded control plane
                if self.values_yaml:
                    values_yaml_data = self.values_yaml
                    values_yaml_str = yaml.dump(values_yaml_data)
                else:
                    values_yaml_str = None

                body = ApiInstallEmbeddedControlPlaneArgs(
                    remote_repo_url=self.get_param("remote_repo_url"),
                    values_yaml=values_yaml_str,
                    experience_cluster_name=self.name,
                    containerized_cluster_name=self.name,
                    datalake_cluster_name=self.datalake_cluster_name,
                    selected_features=self.selected_features,
                )

                command = self.cp_api_instance.install_embedded_control_plane(body=body)
                # Wait for command completion
                command_state = self.wait_for_command_state(
                    command_id=command.id, polling_interval=self.delay,
                )

                # Retry logic if command failed and can be retried
                # command_state is a tuple from read_command_with_http_info, where [0] is the ApiCommand object
                api_command = command_state[0]
                can_retry = getattr(api_command, "can_retry", False)
                success = getattr(api_command, "success", True)
                command_id = getattr(api_command, "id", None)
                # else:
                #     can_retry = getattr(command_state, 'can_retry', False)
                #     success = getattr(command_state, 'success', True)
                #     command_id = getattr(command_state, 'id', None)

                if not success and can_retry and command_id:
                    self.module.warn(
                        f"Command failed but can be retried. Retrying command {command_id}.",
                    )
                    retry_command = self.command_api_instance.api_instance.retry(
                        command_id,
                    )

                    # Wait for command completion
                    command_state = self.wait_for_command_state(
                        command_id=retry_command.id, polling_interval=self.delay,
                    )

            else:  # TODO: Install external control plane
                pass
                # # # Install external control plane
                # if self.values_yaml:
                #   values_yaml_data = self.values_yaml
                #   values_yaml_str = yaml.dump(values_yaml_data)
                # else:
                #     values_yaml_str = None

                # body = ApiInstallControlPlaneArgs(
                #     kubernetes_type=self.kubernetes_type,
                #     remote_repo_url=self.get_param('remote_repo_url'),
                #     values_yaml=values_yaml_str,
                #     kube_config=self.kubeconfig,
                #     namespace=self.namespace,
                #     is_override_allowed=self.is_override_allowed
                # )

                # command = api_instance.install_control_plane(body=body)

            # Get the installed control plane info
            updated_cps = self.cp_api_instance.get_control_planes().items

            # if updated_cps and hasattr(updated_cps, 'items'):
            #     updated_cps_list = updated_cps.items
            # elif updated_cps and isinstance(updated_cps, list):
            #     updated_cps_list = updated_cps
            # elif updated_cps:
            #     updated_cps_list = [updated_cps]

            if self.name:
                existing_experience_cluster = parse_cluster_result(
                    self.cluster_api_instance.read_cluster(cluster_name=self.name),
                )
            else:
                existing_experience_cluster = None

            # Find the newly installed control plane
            new_cp = self._find_matching_control_plane(
                updated_cps, existing_experience_cluster,
            )
            if new_cp:
                self.output = parse_control_plane_result(new_cp)

            self.msg = f"Successfully installed {self.type} control plane"

        except ApiException as e:
            self.module.fail_json(
                msg=f"Failed to install {self.type} control plane: {str(e)}",
                details=str(e),
            )

    def _uninstall_control_plane(self, experience_cluster):
        """Uninstall a control plane.
        For embedded control planes, this will delete the associated experience cluster."""

        try:

            if self.type == "embedded":

                if experience_cluster["entity_status"] != "STOPPED":
                    stop = self.cluster_api_instance.stop_command(
                        cluster_name=self.name,
                    )
                    # self.wait_command(stop, polling=self.timeout, delay=self.delay)
                    self.wait_for_command_state(
                        command_id=stop.id, polling_interval=self.delay,
                    )

                delete = self.cluster_api_instance.delete_cluster(
                    cluster_name=self.name,
                )
                self.wait_command(delete, polling=self.timeout, delay=30)

            else:  # TODO: Remove External control plane
                pass

        except ApiException as e:
            self.module.fail_json(
                msg=f"Failed to uninstall control plane: {str(e)}", details=str(e),
            )


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            state=dict(type="str", default="present", choices=["present", "absent"]),
            type=dict(type="str", choices=["external", "embedded"], required=True),
            namespace=dict(type="str"),
            remote_repo_url=dict(type="str"),
            values_yaml=dict(type="dict", aliases=["control_plane_config"]),
            name=dict(
                type="str", aliases=["containerized_cluster_name", "control_plane_name"],
            ),
            datalake_cluster_name=dict(type="str"),
            selected_features=dict(type="list", elements="str"),
            kubernetes_type=dict(type="str"),
            kubeconfig=dict(type="str"),
            is_override_allowed=dict(type="bool"),
        ),
        required_if=[
            ("type", "external", ["namespace", "kubernetes_type"]),
            ("type", "embedded", ["name"]),
        ],
        supports_check_mode=True,
    )

    result = ControlPlane(module)

    output = dict(
        changed=result.changed,
        control_plane=result.output,
        msg=result.msg,
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
