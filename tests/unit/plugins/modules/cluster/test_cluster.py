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

from ansible.module_utils.common.dict_transformations import recursive_diff

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

    # if os.getenv("CM_PROXY", None):
    #     conn.update(proxy=os.getenv("CM_PROXY"))

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
        name="Example_Base",
        cluster_version="7",  # "1.5.1-b626.p0.42068229",
        type="BASE_CLUSTER",
        state="present",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))


def test_present_base_hosts(conn, module_args):
    conn.update(
        name="Example_Base_Hosts",
        cluster_version="7",  # "1.5.1-b626.p0.42068229",
        type="BASE_CLUSTER",
        state="present",
        hosts={
            "test09-worker-free-01.cldr.internal": {},
        },
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))


def test_present_base_hosts_not_found(conn, module_args):
    conn.update(
        name="Example_Base_Hosts_Not_Found",
        cluster_version="7",  # "1.5.1-b626.p0.42068229",
        type="BASE_CLUSTER",
        state="present",
        hosts={
            "should.not.find": {},
        },
    )
    module_args(conn)

    with pytest.raises(
        AnsibleFailJson, match="Did not find the following hosts: should.not.find"
    ):
        cluster.main()


def test_present_base_hosts_in_use(conn, module_args):
    conn.update(
        name="Example_Base_Hosts_In_Use",
        cluster_version="7",  # "1.5.1-b626.p0.42068229",
        type="BASE_CLUSTER",
        state="present",
        hosts={
            "test09-worker-02.cldr.internal": {},
        },
    )
    module_args(conn)

    with pytest.raises(AnsibleFailJson, match="Invalid host reference!"):
        cluster.main()


def test_present_base_auto_assign(conn, module_args):
    conn.update(
        name="Example_Base",
        cluster_version="7",  # "1.5.1-b626.p0.42068229",
        type="BASE_CLUSTER",
        state="present",
        auto_assign=True,
        hosts={
            "test09-worker-free-01.cldr.internal": {},
        },
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))

    #   ZOOKEEPER:
    #     SERVICEWIDE:
    #       zookeeper_datadir_autocreate: true
    #       service_config_suppression_server_count_validator: true
    #     SERVER:
    #       zookeeper_server_java_heapsize: 134217728


def test_present_base_service(conn, module_args):
    conn.update(
        name="Example_Base_Service",
        cluster_version="7",  # "1.5.1-b626.p0.42068229",
        type="BASE_CLUSTER",
        state="present",
        services=[
            dict(
                name="Example_ZK",
                type="ZOOKEEPER",
                display_name="ZK_TEST",
                config=dict(
                    zookeeper_datadir_autocreate=True,
                    service_config_suppression_server_count_validator=True,
                ),
                role_config_groups=[
                    dict(
                        name="BASE-SERVER", #  ignored due to base=True
                        type="SERVER",
                        display_name="Server Base Group",
                        base=True,
                        config=dict(
                            zookeeper_server_java_heapsize=134217728,
                        ),
                    ),
                    dict(
                        name="NON-BASE-SERVER",
                        type="SERVER",
                        display_name="Server Custom Group",
                        config=dict(
                            zookeeper_server_java_heapsize=33554432,
                        ),
                    ),
                ],
            ),
        ],
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))


def test_started_base(conn, module_args):
    conn.update(
        name="PVC-Base",
        cluster_version="7.1.9",  # "1.5.1-b626.p0.42068229",
        # type="COMPUTE_CLUSTER",
        state="started",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))


def test_restarted_base(conn, module_args):
    conn.update(
        name="PVC-Base",
        cluster_version="7.1.9",  # "1.5.1-b626.p0.42068229",
        # type="COMPUTE_CLUSTER",
        state="restarted",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))


def test_stopped_base(conn, module_args):
    conn.update(
        name="PVC-Base",
        cluster_version="7.1.9",  # "1.5.1-b626.p0.42068229",
        # type="COMPUTE_CLUSTER",
        state="stopped",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))


def test_absent_base(conn, module_args):
    conn.update(
        name="Example_Base",
        state="absent",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))


def test_present_compute_minimum(conn, module_args):
    conn.update(
        name="Example_Compute",
        cluster_version="7.1.9",  # "1.5.1-b626.p0.42068229",
        # type="COMPUTE_CLUSTER",
        contexts=["SDX"],
        state="present",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))


def test_started_compute_minimum(conn, module_args):
    conn.update(
        name="Example_Compute",
        cluster_version="7.1.9",  # "1.5.1-b626.p0.42068229",
        # type="COMPUTE_CLUSTER",
        contexts=["SDX"],
        state="started",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))


def test_absent_compute(conn, module_args):
    conn.update(
        name="Example_Compute",
        state="absent",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))


def test_present_experience_minimum(conn, module_args):
    conn.update(
        name="Example_Experience",
        cluster_version="1.5.1",  # "1.5.1-b626.p0.42068229",
        type="EXPERIENCE_CLUSTER",
        state="present",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))


def test_absent_experience(conn, module_args):
    conn.update(
        name="Example_Experience",
        state="absent",
    )
    module_args(conn)

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    # LOG.info(str(e.value))
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
        }
    )

    with pytest.raises(AnsibleExitJson) as e:
        cluster.main()

    # LOG.info(str(e.value))
    LOG.info(str(e.value.cloudera_manager))
