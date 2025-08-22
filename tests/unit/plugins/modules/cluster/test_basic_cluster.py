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


def test_present(conn, module_args):
    args = """
    name: Basic_Cluster
    cluster_version: "7.1.9-1.cdh7.1.9.p0.44702451"
    type: BASE_CLUSTER
    state: present
    services:
      - name: core-settings-0
        type: CORE_SETTINGS
        display_name: CORE_SETTINGS_TEST
      - name: zookeeper-0
        type: ZOOKEEPER
        display_name: ZK_TEST
        config:
          zookeeper_datadir_autocreate: yes
      - name: hdfs-0
        type: HDFS
        display_name: HDFS_TEST
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
        display_name: YARN_TEST
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
              yarn_nodemanager_local_dirs:  /tmp/nm
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
      - name: test10-worker-free-01.cldr.internal
        host_template: Master1
      - name: test10-worker-free-02.cldr.internal
        host_template: Worker
      - name: test10-worker-free-03.cldr.internal
        host_template: Worker
    """
    conn.update(yaml.safe_load(args))
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_started(conn, module_args):
    args = """
    name: Basic_Cluster
    state: started
    """
    conn.update(yaml.safe_load(args))
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_restarted(conn, module_args):
    args = """
    name: Basic_Cluster
    state: restarted
    """
    conn.update(yaml.safe_load(args))
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_stopped(conn, module_args):
    args = """
    name: Basic_Cluster
    state: stopped
    """
    conn.update(yaml.safe_load(args))
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_absent(conn, module_args):
    args = """
    name: Basic_Cluster
    state: absent
    """
    conn.update(yaml.safe_load(args))
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))
