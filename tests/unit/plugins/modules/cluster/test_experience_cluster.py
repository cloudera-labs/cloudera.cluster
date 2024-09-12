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

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
import os
import pytest
import yaml

from ansible_collections.cloudera.cluster.plugins.modules import cluster
from ansible_collections.cloudera.cluster.tests.unit import (
    AnsibleExitJson,
    AnsibleFailJson,
)

LOG = logging.getLogger(__name__)


@pytest.fixture
def conn():
    conn = dict(username=os.getenv("CM_USERNAME"), password=os.getenv("CM_PASSWORD"))

    if os.getenv("CM_HOST", None):
        conn.update(host=os.getenv("CM_HOST"))

    if os.getenv("CM_PORT", None):
        conn.update(port=os.getenv("CM_PORT"))

    if os.getenv("CM_ENDPOINT", None):
        conn.update(url=os.getenv("CM_ENDPOINT"))

    if os.getenv("CM_PROXY", None):
        conn.update(proxy=os.getenv("CM_PROXY"))

    return {
        **conn,
        "verify_tls": "no",
        "debug": "no",
    }


def test_experience_cluster(conn, module_args):
    args = """
    name: PVC-ECS
    type: EXPERIENCE_CLUSTER
    state: present
    cluster_version: "1.5.4-111-ecs-1.5.4-111.p0.11111"
    parcels:
      ECS: "1.5.4-111-ecs-1.5.4-111.p0.11111"
    services:
      - name: docker
        type: DOCKER
        display_name: docker
        config:
          docker_images_destination_registry_user: registry-user
          defaultDataPath: /mnt/docker
      - name: ecs
        type: ECS
        display_name: ECS
        config:
          app_domain: test.lab.example
          k8s_webui_secret_admin_token: ecs-k8s_webui_secret_admin_token
          cp_prometheus_ingress_user: cloudera-manager
          infra_prometheus_ingress_user: cloudera-manager
          longhorn_replication: 2
          lsoDataPath: /ecs/local
          docker: docker
          cp_prometheus_ingress_password: Pasword123
          infra_prometheus_ingress_password: Pasword123
          defaultDataPath: /ecs/longhorn-storage
          nfs_over_provisioning: 800
    host_templates:
      - name: ecs_master
        role_groups:
          - service_name: docker
            type: DOCKER_SERVER
          - service_name: ecs
            type: ECS_SERVER
      - name: ecs_workers
        role_groups:
          - service_name: docker
            type: DOCKER_SERVER
          - service_name: ecs
            type: ECS_AGENT
    hosts:
      - name: ecs-m-01.test.lab.example
        host_template: ecs_master
      - name: ecs-w-01.test.lab.example
        host_template: ecs_workers
      - name: ecs-w-02.test.lab.example
        host_template: ecs_workers
      - name: ecs-w-03.test.lab.example
        host_template: ecs_workers
    control_plane:
      datalake_cluster_name: PVC-Base
      remote_repo_url: "https://my.domain/cdp-pvc-ds/1.5.4"
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
    conn.update(yaml.safe_load(args))
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_experience_cluster_defined_role_groups(conn, module_args):
    args = """
    name: PVC-ECS
    type: EXPERIENCE_CLUSTER
    state: present
    cluster_version: "1.5.4-1.5.4-b99.p0.111111"
    parcels:
      ECS: "1.5.4-1.5.4-b99.p0.111111"
    services:
      - name: docker
        type: DOCKER
        display_name: docker
        config:
          docker_images_destination_registry_user: registry-user
          defaultDataPath: /mnt/docker
      - name: ecs
        type: ECS
        display_name: ECS
        config:
          app_domain: test.lab.example
          k8s_webui_secret_admin_token: ecs-k8s_webui_secret_admin_token
          cp_prometheus_ingress_user: cloudera-manager
          infra_prometheus_ingress_user: cloudera-manager
          longhorn_replication: 2
          lsoDataPath: /ecs/local
          docker: docker
          cp_prometheus_ingress_password: Pasword123
          infra_prometheus_ingress_password: Pasword123
          defaultDataPath: /ecs/longhorn-storage
          nfs_over_provisioning: 800
    host_templates:
      - name: ecs_master
        role_groups:
          - ref: docker-DOCKER_SERVER-BASE
          - ref: ecs-ECS_SERVER-BASE
      - name: ecs_workers
        role_groups:
          - ref: docker-DOCKER_SERVER-BASE
          - ref: ecs-ECS_AGENT-BASE
    hosts:
      - name: ecs-m-01.test.lab.example
        host_template: ecs_master
      - name: ecs-w-01.test.lab.example
        host_template: ecs_workers
      - name: ecs-w-02.test.lab.example
        host_template: ecs_workers
      - name: ecs-w-03.test.lab.example
        host_template: ecs_workers
    control_plane:
      datalake_cluster_name: PVC-Base
      remote_repo_url: "https://my.domain/cdp-pvc-ds/1.5.4"
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
    conn.update(yaml.safe_load(args))
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))
