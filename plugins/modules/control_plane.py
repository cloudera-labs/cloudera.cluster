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
from ansible.module_utils.common.validation import check_missing_parameters
from ansible.module_utils.common.text.converters import to_native

from cm_client.rest import ApiException

DOCUMENTATION = r"""
module: control_plane
short_description: Manage Cloudera control planes
description:
  - Manage the lifecycle and state of control planes in Cloudera on-premise deployments.
  - Install, uninstall, and manage both normal and K8s embedded control planes.
  - Check for existing control planes and handle idempotency.
author:
  - "Jim Enright (@jimright)"
version_added: 5.0.0
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
      - The name of the Experience Cluster associated with the control plane.
      - Required for O(type=embedded) control planes.
    type: str
    required: false
    aliases:
      - containerized_cluster_name
      - control_plane_name
  datalake_cluster_name:
    description:
      - The name of the datalake base cluster associated with the control plane.
      - Required when creating O(state=present) for embedded control plane O(type=embedded).
    type: str
    required: false
  namespace:
    description:
      - The Kubernetes namespace where the control plane should be installed.
      - Required for external control planes, O(type=external).
    type: str
    required: false
  features:
    description:
      - The list of features to enable in the control plane.
      - Only used during creation O(state=present) of embedded control planes O(type=embedded).
    type: list
    elements: str
    required: false
    aliases:
      - selected_features
  remote_repo_url:
    description:
      - The URL of the remote repository where the artifacts used to install the control plane are hosted.
      - Required when O(state=present)
    type: str
    required: false
  control_plane_config:
    description:
      - The content of the values YAML used to configure the control plane.
      - Required when O(state=present).
    type: dict
    required: false
    aliases:
      - values_yaml
  kubernetes_type:
    description:
      - The Kubernetes type on which the control plane should run.
      - Required for external control planes, O(type=external).
    type: str
    required: false
    aliases:
      - external_k8s_type
  kubeconfig:
    description:
      - The content of the kubeconfig file of the kubernetes environment on which the install will be performed.
      - Required for external control planes, O(type=external).
    type: str
    required: false
  override:
    description:
      - Flag to specify if the control plane installation override existing configurations.
      - Only used during creation O(state=present) of external control planes O(type=external).
    type: bool
    required: false
  delay:
    description:
      - Delay (interval), in seconds, between check for control plane commandstatus check.
    type: int
    default: 15
    aliases:
      - polling_interval
seealso:
  - module: cloudera.cluster.control_plane_info
  - module: cloudera.cluster.cluster
notes:
  - Removing an embedded control plane is not possible with this module.
  - Instead use the M(cloudera.cluster.cluster) module to remove embedded control planes.
"""

EXAMPLES = r"""
- name: Install a external control plane
  cloudera.cluster.control_plane:
    host: "example.cloudera.host"
    username: "admin"
    password: "admin_password"
    state: present
    type: external
    namespace: "example-namespace"
    remote_repo_url: "https://archive.cloudera.com/p/cdp-pvc-ds/1.5.5-h1"
    kubernetes_type: "openshift"
    kubeconfig: "{{ lookup('ansible.builtin.file', 'kubeconfig.yml') }}"
    control_plane_config:
      ContainerInfo:
        Mode: public
        CopyDocker: false
      Database:
        Mode: embedded
        EmbeddedDbStorage: 200
      Vault:
        Mode: embedded
        EmbeddedDbStorage: 20

- name: Install an embedded control plane
  cloudera.cluster.control_plane:
    host: "example.cloudera.host"
    username: "admin"
    password: "admin_password"
    state: present
    name: "example-embedded-cp"
    type: embedded
    datalake_cluster_name: "example-base-cluster"
    remote_repo_url: "https://archive.cloudera.com/p/cdp-pvc-ds/1.5.5-h1"
    control_plane_config:
      ContainerInfo:
        Mode: public
        CopyDocker: false
      Database:
        Mode: embedded
        EmbeddedDbStorage: 200
      Vault:
        Mode: embedded
        EmbeddedDbStorage: 20

- name: Uninstall a control plane
  cloudera.cluster.control_plane:
    host: "example.cloudera.host"
    username: "admin"
    password: "admin_password"
    state: absent
"""

RETURN = r"""
control_plane:
  description: Details about the control plane.
  type: dict
  returned: always
  contains:
    namespace:
      description: The Kubernetes namespace where the control plane is installed.
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
"""

# Constant for the tag used to identify the control plane in Experience Cluster
CONTROL_PLANE_IDENTIFIER_TAG = "_cldr_cm_ek8s_control_plane"


class ControlPlane(ClouderaManagerModule):
    def __init__(self, module):
        super(ControlPlane, self).__init__(module)

        self.state = self.get_param("state")
        self.type = self.get_param("type")
        self.remote_repo_url = self.get_param("remote_repo_url")
        self.control_plane_config = self.get_param("control_plane_config")

        # Embedded Control plane parameters
        self.name = self.get_param("name")
        self.datalake_cluster_name = self.get_param("datalake_cluster_name")
        self.features = self.get_param("features")

        # External Control plane parameters
        self.kubernetes_type = self.get_param("kubernetes_type")
        self.namespace = self.get_param("namespace")
        self.kubeconfig = self.get_param("kubeconfig")
        self.override = self.get_param("override")

        self.delay = self.get_param("delay")

        # Initialize the output
        self.changed = False
        self.output = {}

        # Execute the logic
        self.process()

    @ClouderaManagerModule.handle_process
    def process(self):
        """Process the control plane management operation."""

        # Check parameters that are required depending on control plane type
        if self.type == "embedded" and self.state == "present":
            # Define the required parameters for embedded control plane creation
            embedded_cp_required_params = {
                'name': {'required': True},
                'remote_repo_url': {'required': True},
                'datalake_cluster_name': {'required': True},
            }

            # Get current parameter values
            params = {
              'name': self.name,
              'remote_repo_url': self.remote_repo_url,
              'datalake_cluster_name': self.datalake_cluster_name,
              }
            
            # Check for missing parameters
            try:
              check_missing_parameters(params, embedded_cp_required_params)
            except TypeError as e:
              self.module.fail_json(msg=to_native(e))

        try:
            self.cp_api_instance = ControlPlanesResourceApi(self.api_client)
            current_cps = self.cp_api_instance.get_control_planes().items

        except ApiException as e:
            if e.status == 404:
                current_cps = []

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
                    details=to_native(e),
                )

        # Find matching control plane
        existing_cp = self._find_matching_control_plane(
            current_cps,
            existing_experience_cluster,
        )

        if self.state == "present":
            if existing_cp:
                # Control plane already exists
                self.changed = False
                self.module.warn(
                    "Control plane matching the required parameters already exists. Reconciliation is not currently supported.",
                )
                self.output = parse_control_plane_result(existing_cp)
            else:
                # Install new control plane
                if not self.module.check_mode:
                    self._install_control_plane(self.cp_api_instance, self.cluster_api_instance)
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
                self.module.info(
                    f"Control plane does not exist, nothing to uninstall.",
                )

    def _find_matching_control_plane(self, control_planes: list, experience_cluster: dict) -> bool | None:
        """Find a control plane that matches the target parameters."""
        if not control_planes:
            return None

        # Initialize match
        matches = True

        for cp in control_planes:
            cp_dict = cp.to_dict()

            if self.type == "embedded":

                # Extract the value of the CONTROL_PLANE_IDENTIFIER_TAG from the tags list
                experience_cluster_uuid = experience_cluster.get("tags", {}).get(
                    CONTROL_PLANE_IDENTIFIER_TAG,
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

    def _install_control_plane(self, cp_api_instance: ControlPlanesResourceApi, cluster_api_instance: ClustersResourceApi) -> None:
        """Install a control plane based on the type."""

        try:
            if self.type == "embedded":
                # Install embedded control plane
                if self.control_plane_config:
                    values_yaml_data = self.control_plane_config
                    values_yaml_str = yaml.dump(values_yaml_data)
                else:
                    values_yaml_str = None

                body = ApiInstallEmbeddedControlPlaneArgs(
                    remote_repo_url=self.remote_repo_url,
                    values_yaml=values_yaml_str,
                    experience_cluster_name=self.name,
                    containerized_cluster_name=self.name,
                    datalake_cluster_name=self.datalake_cluster_name,
                    selected_features=self.features,
                )

                # command = cp_api_instance.install_embedded_control_plane(body=body)
                # # Wait for command completion
                # command_state = self.wait_for_command_state(
                #     command_id=command.id,
                #     polling_interval=self.delay,
                # )

                # # Retry logic if command failed and can be retried
                # # command_state is a tuple from read_command_with_http_info, where [0] is the ApiCommand object
                # api_command = command_state[0]
                # can_retry = getattr(api_command, "can_retry", False)
                # success = getattr(api_command, "success", True)
                # command_id = getattr(api_command, "id", None)

                # if not success and can_retry and command_id:
                #     self.module.info(
                #         f"Command failed but can be retried. Retrying command {command_id}.",
                #     )
                #     command_api_instance = CommandsResourceApi(self.api_client)
                #     retry_command = command_api_instance.retry(
                #         command_id,
                #     )

                #     # Wait for command completion
                #     command_state = self.wait_for_command_state(
                #         command_id=retry_command.id,
                #         polling_interval=self.delay,
                #     )

            else:  # TODO: Install external control plane
                pass
                # # # Install external control plane
                # if self.control_plane_config:
                #   values_yaml_data = self.control_plane_config
                #   values_yaml_str = yaml.dump(values_yaml_data)
                # else:
                #     values_yaml_str = None

                # body = ApiInstallControlPlaneArgs(
                #     kubernetes_type=self.kubernetes_type,
                #     remote_repo_url=self.get_param('remote_repo_url'),
                #     values_yaml=values_yaml_str,
                #     kube_config=self.kubeconfig,
                #     namespace=self.namespace,
                #     is_override_allowed=self.override
                # )

                # command = cp_api_instance.install_control_plane(body=body)

            # Get the installed control plane info
            updated_cps = cp_api_instance.get_control_planes().items

            if self.name:
                existing_experience_cluster = parse_cluster_result(
                    cluster_api_instance.read_cluster(cluster_name=self.name),
                )
            else:
                existing_experience_cluster = None

            # Find the newly installed control plane
            new_cp = self._find_matching_control_plane(
                updated_cps,
                existing_experience_cluster,
            )
            if new_cp:
                self.output = parse_control_plane_result(new_cp)

        except ApiException as e:
            self.module.fail_json(
                msg=f"Failed to install {self.type} control plane: {to_native(e)}",
                details=to_native(e),
            )

    def _uninstall_control_plane(self, experience_cluster: dict ) -> None:
        """Uninstall a control plane.
        For embedded control planes, this will delete the associated experience cluster.
        """

        try:

            if self.type == "embedded":

                self.module.info(
                    f"Removing embedded control plane is not possible. Use the cloudera.cluster.cluster module to remove the {self.name} experience cluster.",
                )

            else:  # TODO: Remove External control plane
                pass

        except ApiException as e:
            self.module.fail_json(
                msg=f"Failed to uninstall control plane: {to_native(e)}",
                details=to_native(e),
            )


def main():
    module = ClouderaManagerModule.ansible_module(
        argument_spec=dict(
            state=dict(type="str", default="present", choices=["present", "absent"]),
            type=dict(type="str", choices=["external", "embedded"], required=True),
            namespace=dict(type="str"),
            remote_repo_url=dict(type="str"),
            control_plane_config=dict(type="dict", aliases=["values_yaml"]),
            name=dict(
                type="str",
                aliases=["containerized_cluster_name", "control_plane_name"],
            ),
            datalake_cluster_name=dict(type="str"),
            features=dict(type="list", elements="str", aliases=["selected_features"]),
            kubernetes_type=dict(type="str", aliases=["external_k8s_type"]),
            kubeconfig=dict(type="str"),
            override=dict(type="bool"),
            delay=dict(type="int", default=15, aliases=["polling_interval"]),
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
    )

    if result.debug:
        log = result.log_capture.getvalue()
        output.update(debug=log, debug_lines=log.split("\n"))

    module.exit_json(**output)


if __name__ == "__main__":
    main()
