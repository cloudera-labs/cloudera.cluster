# cloudera.cluster API Design

One of the core tenants of the `cloudera.cluster` modules is the management of _role assignments_. That is, a role assignment represents the application of a given service's code to an individual cluster host.

From the perspective of the modules' API, assignments are handled according to the scope of the enclosing entity module, e.g. `service`, `role`, and `host`. In addition, the `host_template` module handles indirect assignment via the implicit `role` associate of each `role_config_group`.

The sections below illustrate the scope of assignments and configuration management for each entity.

# Cluster

Within the *Cluster* module, the order of precedence for a Role assignment to a cluster Host is the following:

1. `type` assignment within `service.roles` (direct)
2. `type` assignment within `hosts.roles` (direct)
3. `role_config_group` assignment within `service.roles` (indirect)
4. `name` or `type` assignment within `hosts.role_config_groups` (indirect)
5. `host_template` assignment within `hosts.host_template` (indirect)

Note that Role Config Groups are _defined_ only within `service.role_config_groups`, and Host Templates are _defined_ only within `host_templates`; no assignment of services are within scope of these parameters.

```yaml
cloudera.cluster.cluster:
	name: # str
	display_name: # str
	version: # str
	type: # enumeration
	state: # enumeration
	template: # json
	repos_appended: # bool
	parcels: # list[str]
	tags: # dict
	contexts: # list[str]
	tls_enabled: # bool
	auto_assignment_enabled: # bool
	maintenance_enabled: # bool
	purge: # bool
	control_plane:
		remote_repo_url: # str
		datalake_cluster_name: # str
		control_plane_config: # yaml
	services:
	  - name: # str
	    display_name: # str
	    type: # enumeration
	    version: # str
	    state: # enumeration -- overridden by cluster.state
	    maintenance_enabled: # bool -- ignored if service.maintenance_enabled is not None
	    config: # dict
	    tags: # dict
	    roles: # Assignment -- see role module
		  - type: # str
		    hostnames: # list[str] -- allows for multiple assignment
		    host_ids: # list[str] -- allows for mulitple assignment
		    state: # enumeration -- overridden by service
		    maintenance_enabled: # bool -- ignored if cluster.maintenance_enabled is not None
		    config: # dict
		    role_config_group: # str
		    tags: # dict
		role_config_groups: # Definition only
		  - name: # str
		    display_name: # str
		    type: # str
		    config: # dict
	host_templates: # See host_template module
	  - name: # str
	    role_config_groups: # Reference-only
	      - name: # str
	        type: # str
	        service: # str
	        service_type: # str
	hosts: # See host module
	  - hostnames: # list[str] -- allows for multiple assignment
	    host_ids: # list[str] -- allows for multiple assignment
		config: # dict
		host_template: # str
		role_config_groups: # Reference-only
		  - service: # str
		    name: # str
		    type: # str
		roles: # Assignment
		  - service: # str
		    type: # str
		    config: # dict
```

The `purge` flag will affect the following parameters:

- `parcels`
- `tags`
- `contexts`
- `services.config` _(i.e. service-wide configuration)_
- `services.tags`
- `services.roles`
- `services.roles.hostnames`
- `services.roles.host_ids`
- `services.roles.config` _(i.e. per-host role configuration overrides)_
- `services.roles.tags`
- `services.role_config_groups`
- `services.role_config_groups.config` _(i.e. shared role configuration)_
- `host_templates`
- `host_templates.role_config_groups`
- `hosts`
- `hosts.hostnames`
- `hosts.host_ids`
- `hosts.config`
- `hosts.role_config_groups` _(i.e. indirect assignment)_
- `hosts.roles` _(i.e. direct assignment)_
- `hosts.roles.config` _(i.e. direct per-host role configuration overrides)_

# Service

Within the *Service* module, Role assignments are handled directly in the `roles` option. Role Config Groups are simply a definition and not an assignment.

```yaml
cloudera.cluster.service:
	name: # str
	display_name: # str
	type: # enumeration
	version: # str
	state: # enumeration
	maintenance_enabled: # bool
	purge: # bool
	config: # dict
	tags: # dict
	roles: # Assignment -- see role module
	  - type: # str
		hostnames: # list[str] -- allows for multiple assignment
		host_ids: # list[str] -- allows for mulitple assignment
		state: # enumeration -- overridden by service
		maintenance_enabled: # bool -- ignored if service.maintenance_enabled is not None
		config: # dict
		role_config_group: # str
		tags: # dict
	role_config_groups: # Definition only
	  - name: # str
		display_name: # str
		type: # str
		config: # dict
```

The `purge` flag will affect the following parameters:

- `config` _(i.e. service-wide configuration)_
- `tags`
- `roles`
- `roles.hostnames`
- `roles.host_ids`
- `roles.config` _(i.e. per-host role configuration overrides)_
- `roles.tags`
- `role_config_groups`
- `role_config_groups.config` _(i.e. shared role configuration)_

# Role

Within the *Role* module, assignment is managed directly for a single Role on an individual Host.

```yaml
cloudera.cluster.role:
	name: # str -- Reference-only, as role names are auto-generated
	type: # str
	cluster_hostname: # str
	cluster_host_id: # str
	state: # enumeration
	maintenance_enabled: # bool
	purge: # bool
	config: # dict
	role_config_group: # str
	tags: # dict
```

The `purge` flag will affect the following parameters:

- `config`
- `tags`

# Role Config Group

Within the *Role Config Group* module, there is no Role assignment. The module only manages a single Role Config Group and its configuration.

```yaml
cloudera.cluster.role_config_group:
	name: # str
	display_name: # str
	type: # str
	purge: # bool
	config: # dict
```

The  `purge` flag will affect the following parameters:

- `config`

# Host

Within the *Host* module, assignments are both direct, via the `roles` option, and indirect, via the `role_config_groups` and `host_template` options.

```yaml
cloudera.cluster.host:
	name: # str
	host_id: # str
	config: # dict
	host_template: # str
	purge: # bool
	role_config_groups: # Reference-only
	  - service: # str
		name: # str
		type: # str
	roles: # Assignment
	  - service: # str
		type: # str
		config: # dict
```

The  `purge` flag will affect the following parameters:

- `config`
- `role_config_groups`
- `roles`
- `roles.config` _(i.e. per-host role configuration overrides)_

# Host Template

Within the *Host Template* module, there is no Role assignment. The module only manages a single Host Template and its configuration.

```yaml
cloudera.cluster.host_template:
	name: # str
	role_config_groups: # Reference-only
	  - name: # str
		type: # str
		service: # str
		service_type: # str
```

The  `purge` flag will affect the following parameters:
- `role_config_groups`
