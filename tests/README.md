# Integration Testing

## Fixtures, Factories, and Closures

The collection uses `pytest` fixtures that wrap and yield resource factories.

```python
from ansible_collections.cloudera.cluster.tests.unit import (
    deregister_role,
    deregister_service,
    register_role,
    register_service,
)
```

The example below is a shared ZooKeeper service, scoped to all the tests within a module/file. Once all of the tests are run, the fixture will then destroy the service.

Note, in the following examples:
- `base_cluster` is a session-scoped fixture that either creates a new or references an existing cluster (`ApiCluster`) within the target deployment.
- `cm_api_client` is a session-scoped fixture that returns a shared Cloudera Manager API client object (`ApiClient`).
- `read_roles()` is a utility function in `role_utils.py` that queries Cloudera Manager for all roles and their configurations according to given inputs.
- `create_role()` is a utility function in `role_utils.py` that constructs a well-formed `ApiRole` designed for provisioning or updating a service role.
- `get_service_hosts()` is a utility function in `service_utils.py` that queries Cloudera Manager for all hosts used by a service's roles withing a given cluster.

```python
@pytest.fixture(scope="module")
def zookeeper(cm_api_client, base_cluster):

    # Keep track of the provisioned service(s)
    service_registry = list[ApiService]()

    # Get the current cluster hosts
    hosts = read_roles(
        api_client=api_client,
        cluster_name=service.cluster_ref.cluster_name,
        service_name=service.name,
        type="SERVER",
    ).items

    # Set up the ZooKeeper service
    expected_service = ApiService(
        name="test-zk-service",
        type="ZOOKEEPER",
        display_name="Test ZooKeeper",
        roles = [
            ApiRole(type="SERVER", host_ref=ApiHostRef(hosts[0].host_id))
        ]
    )

    # Provision and then yield the service
    yield register_service(
        api_client=cm_api_client,
        registry=service_registry,
        cluster=base_cluster,
        service=expected_service
    )

    # Remove the service
    deregister_service(
        api_client=cm_api_client,
        registry=service_registry
    )
```

In this case, a `pytest` test invokes the `zookeeper` fixture.  In turn, the `zookeeper` fixture sets up a closure; it prepares a registry (a list of `ApiService`), prepares a couple of inputs, and then yields to the `register_service` function.  This "factory" function creates and configures the service, adds it to the closure's registry, and then _returns_ the resulting `ApiService`. That is, the `register_service` function returns an `ApiService` directly to the invoking `pytest` test.

When the test exits, the flow returns to the point of the `yield` of the `zookeeper` closure and executes the `deregister_service` function, which simply takes each registered service and deletes it.

You can also organizing tests by class and use this technique. In this case, we are using the class to encapsulate additional shared resources -- another (second) `SERVER` role.

```python
class TestZooKeeperService:

    # All tests within this class should have a second SERVER role set up
    @pytest.fixture(scope="class", autouse=True)
    def second_server_role(self, cm_api_client, zookeeper):
        # Keep track of the provisioned role(s)
        role_registry = list[ApiRole]()

        LOG.info("ZooKeeper Service name: " + zookeeper.name)

        existing_role_instances = [
            r.host_ref.hostname
            for r in read_roles(
                api_client=api_client,
                cluster_name=service.cluster_ref.cluster_name,
                service_name=service.name,
                type="SERVER",
            ).items
        ]

        hosts = [
            h
            for h in get_service_hosts(cm_api_client, zookeeper)
            if h.hostname not in existing_role_instances
        ]

        second_role = create_role(
            api_client=cm_api_client,
            role_type="SERVER",
            hostname=hosts[0].hostname,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
        )

        yield register_role(
            api_client=cm_api_client,
            registry=role_registry,
            service=zookeeper,
            role=second_role,
        )

        deregister_role(
            api_client=cm_api_client,
            registry=role_registry
        )
```

The collection has a couple of predefined, _closure_ fixtures in `conftest.py`. The example tests below use a combination of the fixtures defined above and the `role_factory` fixture to assemble 3 `SERVER` roles for a given test.

```python
    def test_server_role_started(self, cm_api_client, zookeeper, role_factory):
        # Find an unused cluster host
        existing_role_instances = [
            r.host_ref.hostname
            for r in read_roles(
                api_client=api_client,
                cluster_name=service.cluster_ref.cluster_name,
                service_name=service.name,
                type="SERVER",
            ).items
        ]

        hosts = [
            h
            for h in get_service_hosts(cm_api_client, zookeeper)
            if h.hostname not in existing_role_instances
        ]

        # Create a new SERVER role
        third_server_role = create_role(
            api_client=cm_api_client,
            role_type="SERVER",
            hostname=hosts[0].hostname,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
        )

        # Provision the SERVER role
        zk_server_role = role_factory(zookeeper, third_server_role)

        LOG.info("ZooKeeper Server role name: " + zk_server_role.name)

        # Now grab all of the SERVER roles from the ZK service
        expected_roles = gather_server_roles(cm_api_client, zookeeper)

        assert len(expected_roles) == 3


    def test_server_role_stopped(self, cm_api_client, zookeeper, role_factory):
        # Find an unused cluster host
        existing_role_instances = [
            r.host_ref.hostname
            for r in read_roles(
                api_client=api_client,
                cluster_name=service.cluster_ref.cluster_name,
                service_name=service.name,
                type="SERVER",
            ).items
        ]

        hosts = [
            h
            for h in get_service_hosts(cm_api_client, zookeeper)
            if h.hostname not in existing_role_instances
        ]

        # Create a new SERVER role
        another_third_server_role = create_role(
            api_client=cm_api_client,
            role_type="SERVER",
            hostname=hosts[0].hostname,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
            role_state = ApiRoleState.STOPPED,
        )

        # Provision the SERVER role
        zk_server_role = role_factory(zookeeper, another_third_server_role)

        LOG.info("ZooKeeper Server role name: " + zk_server_role.name)

        # Now grab all of the SERVER roles from the ZK service
        expected_roles = gather_server_roles(cm_api_client, zookeeper)

        assert len(expected_roles) == 3
```

You should notice that the `second_server_role` fixture is both a _class_-scoped fixture AND is defined within a class. We have another class, but this time, we do not have a second `SERVER` role because the fixture in `TestZooKeeperService`, while scoped to 'class', is declared within that class, not this one. If we had declared the fixture outside of the class, then both classes would run that fixture separately.

```python
class TestZooKeeperServiceAgain:
    # Some other class-wide update
    @pytest.fixture(scope="class", autouse=True)
    def patch_zookeeper_config(cm_api_client, zookeeper):
        LOG.info("Patching ZooKeeper service here.")

    def test_server_role_again(self, cm_api_client, zookeeper, role_factory):
        LOG.info("ZooKeeper Service name: " + zookeeper.name)

        existing_role_instances = [
            r.host_ref.hostname
            for r in read_roles(
                api_client=api_client,
                cluster_name=service.cluster_ref.cluster_name,
                service_name=service.name,
                type="SERVER",
            ).items
        ]

        hosts = [
            h
            for h in get_service_hosts(cm_api_client, zookeeper)
            if h.hostname not in existing_role_instances
        ]

        second_server_role = create_role(
            api_client=cm_api_client,
            role_type="SERVER",
            hostname=hosts[0].hostname,
            cluster_name=zookeeper.cluster_ref.cluster_name,
            service_name=zookeeper.name,
        )

        zk_server_role = role_factory(zookeeper, second_server_role)

        LOG.info("ZooKeeper Server role name: " + zk_server_role.name)

        expected_roles = gather_server_roles(cm_api_client, zookeeper)

        assert len(expected_roles) == 2
```

The last item to notice is that the `zookeeper` service fixture is _module_-scoped, so is available anywhere within the module, i.e. file.  In the example below, this "standalone" test uses the predefined `role_config_group_factory` to create a new role config group and update the base role config group for the `SERVER` role type of the `zookeeper` service.

```python
def test_zookeeper_server_rcg(cm_api_client, zookeeper, role_config_group_factory):

    # Create a custom role config group and update the base role config group
    custom_rcg = role_config_group_factory(zookeeper, ApiRoleConfigGroup(
            name="zk-custom-rcg",
            role_type="SERVER",
            display_name="Custom Server RCG",
            config=ApiConfigList(
                items=[ApiConfig(name="minSessionTimeout", value=4001)],
            ),
        )
    )

    base_rcg = role_config_group_factory(zookeeper, ApiRoleConfigGroup(
            role_type="SERVER",
            config=ApiConfigList(
                items=[ApiConfig(name="minSessionTimeout", value=3999)],
            ),
        )
    )

    LOG.info("Service Name: " + zookeeper.name)
    LOG.info("Custom Role Config Group: " + custom_rcg.name)
    LOG.info("Base Role Config Group: " + base_rcg.name)

    # We haven't created any new SERVER roles, so we should find just the single role created during the service provisioning.
    expected_roles = read_roles(
        api_client=cm_api_client,
        cluster_name=zookeeper.cluster_ref.cluster_name,
        service_name=zookeeper.name,
        type="SERVER",
    ).items

    assert len(expected_roles) == 1
```

## Chaining fixture factories

We can get pretty slick by chaining "closure" fixtures together. For example, we can define a `server_role` fixture for creating a target ZooKeeper `SERVER` role, but then also create "amending" fixtures that further modify the closure-provisioned role.

```python
@pytest.fixture(scope="module")
def zookeeper(cm_api_client, base_cluster, request):
    # Keep track of the provisioned service(s)
    service_registry = list[ApiService]()

    # Get the current cluster hosts
    hosts = get_cluster_hosts(cm_api_client, base_cluster)

    id = Path(request.node.parent.name).stem

    zk_service = ApiService(
        name=f"test-zk-{id}",
        type="ZOOKEEPER",
        display_name=f"ZooKeeper ({id})",
        # Add a SERVER role (so we can start the service -- a ZK requirement!)
        roles=[ApiRole(type="SERVER", host_ref=ApiHostRef(hosts[0].host_id))],
    )

    # Provision and yield the created service
    yield register_service(
        api_client=cm_api_client,
        registry=service_registry,
        cluster=base_cluster,
        service=zk_service,
    )

    # Remove the created service
    deregister_service(api_client=cm_api_client, registry=service_registry)


@pytest.fixture()
def server_role(cm_api_client, zookeeper):
    # Keep track of the provisioned role(s)
    role_registry = list[ApiRole]()

    existing_role_instances = [
        r.host_ref.hostname for r in gather_server_roles(cm_api_client, zookeeper)
    ]

    hosts = [
        h
        for h in get_service_hosts(cm_api_client, zookeeper)
        if h.hostname not in existing_role_instances
    ]

    second_role = create_role(
        api_client=cm_api_client,
        role_type="SERVER",
        hostname=hosts[0].hostname,
        cluster_name=zookeeper.cluster_ref.cluster_name,
        service_name=zookeeper.name,
    )

    yield register_role(
        api_client=cm_api_client,
        registry=role_registry,
        service=zookeeper,
        role=second_role,
    )

    deregister_role(api_client=cm_api_client, registry=role_registry)


# Here, the class is not used for anything but simple organization of tests!
class TestServiceRoleModification:
    @pytest.fixture()
    def updated_server_role_config(self, cm_api_client, server_role):
        RolesResourceApi(cm_api_client).update_role_config(
            cluster_name=server_role.service_ref.cluster_name,
            service_name=server_role.service_ref.service_name,
            role_name=server_role.name,
            body=ApiConfigList(
                items=[
                    ApiConfig(
                        "minSessionTimeout",
                        5000,
                    )
                ]
            ),
        )
        return server_role

    @pytest.fixture()
    def stopped_server_role(self, cm_api_client, server_role):
        stop_cmds = RoleCommandsResourceApi(cm_api_client).stop_command(
            cluster_name=server_role.service_ref.cluster_name,
            service_name=server_role.service_ref.service_name,
            body=ApiRoleNameList(items=[server_role.name]),
        )
        wait_bulk_commands(
            api_client=cm_api_client,
            commands=stop_cmds,
        )
        return server_role


    def test_service_role_existing_config(
        self, conn, module_args, zookeeper, updated_server_role_config
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "name": updated_server_role_config.name,
                "config": {
                    "minSessionTimeout": 5001,
                    "maxSessionTimeout": 50001,
                },
                "state": "present",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == True
        assert e.value.role["type"] == updated_server_role_config.type
        assert e.value.role["hostname"] == updated_server_role_config.host_ref.hostname
        assert e.value.role["role_state"] == ApiRoleState.STARTED
        assert e.value.role["config"]["minSessionTimeout"] == "5001"
        assert e.value.role["config"]["maxSessionTimeout"] == "50001"

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == False
        assert e.value.role["config"]["minSessionTimeout"] == "5001"
        assert e.value.role["config"]["maxSessionTimeout"] == "50001"


    def test_service_role_existing_state_started(
        self, conn, module_args, zookeeper, stopped_server_role
    ):
        module_args(
            {
                **conn,
                "cluster": zookeeper.cluster_ref.cluster_name,
                "service": zookeeper.name,
                "name": stopped_server_role.name,
                "state": "started",
            }
        )

        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == True
        assert e.value.role["type"] == stopped_server_role.type
        assert e.value.role["hostname"] == stopped_server_role.host_ref.hostname
        assert e.value.role["role_state"] == ApiRoleState.STARTED

        # Idempotency
        with pytest.raises(AnsibleExitJson) as e:
            service_role.main()

        assert e.value.changed == False
        assert e.value.role["role_state"] == ApiRoleState.STARTED
```

Happy testing!
