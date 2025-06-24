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


def test_missing_required(conn, module_args):
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="name"):
        cluster.main()


def test_present_base_minimum(conn, module_args):
    conn.update(
        name="Example_Base_Minimum",
        cluster_version="7",  # "1.5.1-b626.p0.42068229",
        type="BASE_CLUSTER",
        state="present",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))
    assert e.value.cloudera_manager


def test_present_base_hosts(conn, module_args):
    conn.update(
        name="Example_Base_Hosts",
        cluster_version="7",  # "1.5.1-b626.p0.42068229",
        type="BASE_CLUSTER",
        state="present",
        hosts=[{"name": "test10-worker-free-01.cldr.internal"}],
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_present_base_hosts_not_found(conn, module_args):
    conn.update(
        name="Example_Base_Hosts_Not_Found",
        cluster_version="7",  # "1.5.1-b626.p0.42068229",
        type="BASE_CLUSTER",
        state="present",
        hosts=[{"name": "should.not.find"}],
    )
    module_args(conn)

    with pytest.raises(
        AnsibleFailJson,
        match="Did not find the following hosts: should.not.find",
    ):
        cluster.main()


def test_present_base_hosts_in_use(conn, module_args):
    conn.update(
        name="Example_Base_Hosts_In_Use",
        cluster_version="7",  # "1.5.1-b626.p0.42068229",
        type="BASE_CLUSTER",
        state="present",
        hosts=[{"name": "test10-worker-02.cldr.internal"}],
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="Invalid host reference!"):
        cluster.main()


def test_present_base_auto_assign(conn, module_args):
    conn.update(
        name="Example_Base_Auto_Assign",
        cluster_version="7",  # "1.5.1-b626.p0.42068229",
        type="BASE_CLUSTER",
        state="present",
        auto_assign=True,
        hosts=[{"name": "test10-worker-free-01.cldr.internal"}],
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_present_base_service(conn, module_args):
    args = """
    name: Example_Base_Service
    cluster_version: 7
    type: BASE_CLUSTER
    state: present
    services:
      - name: ZK-BASE-SERVICE
        type: ZOOKEEPER
        display_name: ZK_TEST
    """
    conn.update(yaml.safe_load(args))
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_present_base_service_config(conn, module_args):
    args = """
    name: Example_Base_Service_Config
    cluster_version: 7
    type: BASE_CLUSTER
    state: present
    services:
      - name: ZK-BASE-SERVICE-CONFIG
        type: ZOOKEEPER
        display_name: ZK_TEST
        config:
          zookeeper_datadir_autocreate: yes
          service_config_suppression_server_count_validator: yes
    """
    conn.update(yaml.safe_load(args))
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_present_base_service_role_groups(conn, module_args):
    args = """
    name: Example_Base_Service_Role_Groups
    cluster_version: 7
    type: BASE_CLUSTER
    state: present
    services:
      - name: ZK-BASE-SERVICE-ROLE-GROUPS
        type: ZOOKEEPER
        display_name: ZK_TEST
        role_groups:
          - type: SERVER
            display_name: Server Base Group
            config:
              zookeeper_server_java_heapsize: 134217728 # 128MB
          - name: NON-BASE-SERVER
            type: SERVER
            display_name: Server Custom Group
            config:
              zookeeper_server_java_heapsize: 33554432  # 32MB
    """
    conn.update(yaml.safe_load(args))
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_present_base_host_role_group_assignment_base(conn, module_args):
    args = """
    name: Example_Base_Host_Role_Group_Assignment
    cluster_version: 7
    type: BASE_CLUSTER
    state: present
    services:
      - name: ZK_HOST_ROLE_GROUP_ASSIGNMENT
        type: ZOOKEEPER
        display_name: ZK_TEST
        role_groups:
          - type: SERVER
            display_name: Server Base Group
            config:
              zookeeper_server_java_heapsize: 134217728 # 128MB
          - name: HOST_ROLE_GROUP_ASSIGNMENT_NON_BASE_SERVER
            type: SERVER
            display_name: Server Custom Group
            config:
              zookeeper_server_java_heapsize: 33554432  # 32MB
    hosts:
      - name: test10-worker-free-02.cldr.internal
        role_groups:
          - type: SERVER
            service: ZK_HOST_ROLE_GROUP_ASSIGNMENT
    """
    conn.update(yaml.safe_load(args))
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_present_base_host_role_group_assignment_custom(conn, module_args):
    args = """
    name: Example_Base_Host_Role_Group_Assignment
    cluster_version: 7
    type: BASE_CLUSTER
    state: present
    services:
      - name: ZK_HOST_ROLE_GROUP_ASSIGNMENT_CUSTOM
        type: ZOOKEEPER
        display_name: ZK_TEST
        role_groups:
          - type: SERVER
            display_name: Server Base Group
            config:
              zookeeper_server_java_heapsize: 134217728 # 128MB
          - name: ZK_HOST_ROLE_GROUP_ASSIGNMENT_CUSTOM_NON_BASE_SERVER
            type: SERVER
            display_name: Server Custom Group
            config:
              zookeeper_server_java_heapsize: 33554432  # 32MB
    hosts:
      - name: test10-worker-free-03.cldr.internal
        role_groups:
          - name: ZK_HOST_ROLE_GROUP_ASSIGNMENT_CUSTOM_NON_BASE_SERVER
            service: ZK_HOST_ROLE_GROUP_ASSIGNMENT_CUSTOM
    """
    conn.update(yaml.safe_load(args))
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_present_base_host_host_template_assignment(conn, module_args):
    args = """
    name: Example_Base_Host_Host_Template_Assignment
    cluster_version: "7.1.9-1.cdh7.1.9.p0.44702451" # 7
    type: BASE_CLUSTER
    state: present
    services:
      - name: ZK-BASE-SERVICE-ROLE-GROUPS
        type: ZOOKEEPER
        display_name: ZK_TEST
        role_groups:
          - name: BASE-SERVER                           # ignored due to base=True
            type: SERVER
            base: yes
            display_name: Server Base Group
            config:
              zookeeper_server_java_heapsize: 134217728 # 128MB
          - name: NON-BASE-SERVER
            type: SERVER
            display_name: Server Custom Group
            config:
              zookeeper_server_java_heapsize: 75497472  # 72MB
    hosts:
      - name: test10-worker-free-01.cldr.internal
        host_template: Example_Template
    host_templates:
      - name: Example_Template
        role_groups:
          - NON-BASE-SERVER
    parcels:
      CDH: "7.1.9-1.cdh7.1.9.p0.44702451"
    """
    conn.update(yaml.safe_load(args))
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_present_base_host_role_overrides(conn, module_args):
    args = """
    name: Example_Base_Host_Role_Overrides
    cluster_version: "7.1.9-1.cdh7.1.9.p0.44702451" # 7
    type: BASE_CLUSTER
    state: present
    services:
      - name: ZK-BASE-SERVICE-ROLE-GROUPS
        type: ZOOKEEPER
        display_name: ZK_TEST
        role_groups:
          - name: NON-BASE-SERVER
            type: SERVER
            display_name: Server Custom Group
            config:
              zookeeper_server_java_heapsize: 75497472  # 72MB
    hosts:
      - name: test10-worker-free-02.cldr.internal
        roles:
          - service: ZK-BASE-SERVICE-ROLE-GROUPS
            type: SERVER
            config:
              zookeeper_server_java_heapsize: 67108864 # 64MB
        host_template: Example_Template
    host_templates:
      - name: Example_Template
        role_groups:
          - NON-BASE-SERVER
    parcels:
      CDH: "7.1.9-1.cdh7.1.9.p0.44702451"
    """
    conn.update(yaml.safe_load(args))
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_started_base(conn, module_args):
    conn.update(
        name="PVC-Base",
        cluster_version="7.1.9",  # "1.5.1-b626.p0.42068229",
        state="started",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_restarted_base(conn, module_args):
    conn.update(
        name="PVC-Base",
        cluster_version="7.1.9",  # "1.5.1-b626.p0.42068229",
        state="restarted",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_stopped_base(conn, module_args):
    conn.update(
        name="PVC-Base",
        cluster_version="7.1.9",  # "1.5.1-b626.p0.42068229",
        state="stopped",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_absent_base(conn, module_args):
    conn.update(
        name="Example_Base",
        state="absent",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))


def test_pytest_cluster_with_template(module_args):
    module_args(
        {
            "username": os.getenv("CM_USERNAME"),
            "password": os.getenv("CM_PASSWORD"),
            "host": os.getenv("CM_HOST"),
            "port": "7180",
            "verify_tls": "no",
            "debug": "no",
            "cluster_name": "Base_CM_Cluster",
            "template": "./files/cluster-template.json",
            "add_repositories": "True",
            "state": "present",
        },
    )

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    LOG.info(str(e.value.cloudera_manager))
