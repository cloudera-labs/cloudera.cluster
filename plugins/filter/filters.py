#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2023 Cloudera, Inc. All Rights Reserved.
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
from typing import Optional
import re

__metaclass__ = type


class FilterModule(object):

    def filters(self):
        return {
            'flatten_dict_list': self.flatten_dict_list,
            'extract_custom_roles': self.extract_custom_roles,
            'extract_custom_role_groups': self.extract_custom_role_groups,
            'extract_products_from_manifests': self.extract_products_from_manifests,
            'extract_role_and_group': self.extract_role_and_group,
            'format_database_type': self.format_database_type,
            'get_product_version': self.get_product_version,
            'get_major_version': self.get_major_version,  # Unused
            'append_database_port': self.append_database_port,
            'default_database_port': self.default_database_port,
            'get_database_encoding_mysql': self.get_database_encoding_mysql,
            'get_database_collation_mysql': self.get_database_collation_mysql,
            'filter_null_configs': self.filter_null_configs,
            'to_ldap_type_enum': self.to_ldap_type_enum,
            'extract_parcel_urls': self.extract_parcel_urls,
            'cluster_service_role_hosts': self.cluster_service_role_hosts,
            'find_clusters': self.find_clusters
        }

    def flatten_dict_list(self, item, level=2, sep='_', show_index=False):
        """ flatten a structure of dicts and lists into a flat array

        e.g. { "a": [1, 2, 3], "b": { "c": "d", "e": "f" } }
             with level=2
             becomes ["a_1", "a_2", "a_3", "b_c", "b_d"]
        """

        state = []

        def _flatten_dict_list(i, l, parents):
            if l > 0:
                if isinstance(i, dict):
                    for key, value in i.items():
                        _flatten_dict_list(value, l - 1, parents + [str(key)])

                elif isinstance(i, list):
                    for index, value in enumerate(i):
                        if show_index:
                            _flatten_dict_list(value, l, parents + [str(index)])
                        else:
                            _flatten_dict_list(value, l, parents)

                else:
                    state.append(sep.join(parents + [str(i)]))

            if l == 0 and len(parents) > 0:
                state.append(sep.join(parents))

        _flatten_dict_list(item, level, [])

        return state

    def extract_products_from_manifests(self, manifests, os_distribution: Optional[str] = None):
        products = dict()
        for manifest in manifests:
            for parcel in manifest["parcels"]:
                # fetch the full parcel name from the manifest
                full_parcel_name = str(parcel["parcelName"])
                # the parcel OS distribution is between the last "-" and the ".parcel" extension
                parcel_os_distribution = full_parcel_name[
                    full_parcel_name.rindex("-")
                    + 1: full_parcel_name.rindex(".parcel")
                ]
                # take first parcel, strip off OS name and file extension
                parcel_name = re.sub(r"-[a-z0-9]+\.parcel$", "", full_parcel_name)
                # the product name is before the first dash
                product = parcel_name[: parcel_name.index("-")]
                if product not in products and (
                    os_distribution == parcel_os_distribution or os_distribution is None
                ):
                    # the version string is everything after the first dash
                    version = parcel_name[parcel_name.index("-") + 1:]
                    products[product] = version
        return products

    def extract_parcel_urls(self, manifest_results):
        parcels = list()
        for result in manifest_results:
            manifest_url = result['invocation']['module_args']['url']
            base_url = '/'.join(manifest_url.rsplit('/')[:-1])
            parcel_names = [x['parcelName'] for x in result['json']['parcels']]
            parcels += ['/'.join([str(base_url), str(y)]) for y in parcel_names]
        return parcels

    def format_database_type(self, database_type):
        if database_type == "mariadb":
            return "mysql"
        return database_type.lower()

    def get_product_version(self, products, product_name):
        for product in products:
            if product['product'] == product_name:
                version = product['version']
                return version[:version.index('-')] if "-" in version else version

    def get_major_version(self, products, product_name):
        version = self.get_product_version(products, product_name)
        if version:
            return version.split('.')[0]

    def append_database_port(self, database_host, database_port=None):
        if ":" not in database_host and database_port:
            return database_host + ":" + database_port
        return database_host

    def default_database_port(self, database_type):
        if database_type == "postgresql":
            return 5432
        if database_type == "mysql" or database_type == "mariadb":
            return 3306
        if database_type == "oracle":
            return 1521
        return None

    def get_database_encoding_mysql(self, service_name):
        # workaround for https://jira.cloudera.com/browse/CDPD-9290
        if service_name == "RANGER":
            database_encoding = "latin1"
        else:
            database_encoding = "utf8"
        return database_encoding

    def get_database_collation_mysql(self, service_name):
        # workaround for https://jira.cloudera.com/browse/CDPD-9290
        if service_name == "RANGER":
            database_collation = "latin1_swedish_ci"
        else:
            database_collation = "utf8_general_ci"
        return database_collation

    def filter_null_configs(self, configs, existing_configs):
        filtered_configs = dict(configs)
        for item, value in configs.items():
            if item not in existing_configs and not value:
                del filtered_configs[item]
        return filtered_configs

    def to_ldap_type_enum(self, s):
        if s == "AD":
            return "ACTIVE_DIRECTORY"
        return s.replace(" ", "_").upper()

    def cluster_service_role_hosts(self, cluster, hostvars, service, roles=None):
        candidate_templates = []

        if 'host_templates' in cluster:
            templates = cluster['host_templates']

            if roles:
                for role in roles:
                    for t_name, t_services in templates.items():
                        if service in t_services and role in t_services[service]:
                            if t_name not in candidate_templates:
                                candidate_templates.append(t_name)

            else:
                for t_name, t_services in templates.items():
                    if service in t_services:
                        candidate_templates.append(t_name)

        hosts = []
        for t_name in candidate_templates:
            t_hosts = [
                host
                for host, hostvar in hostvars.items()
                if host not in hosts
                if hostvar.get('host_template') == t_name]

            hosts = hosts + t_hosts

        return hosts

    def find_clusters(self, clusters, name):
        return [
            cluster
            for cluster in clusters
            if cluster.get('name') == name]

    def extract_role_and_group(self, role_spec):
        role = None
        template_group = "BASE"
        if '/' in role_spec:
            role = role_spec[:role_spec.index('/')]
            template_group = role_spec[role_spec.index('/')+1:]
        else:
            role = role_spec
        return (role, template_group)

    def extract_custom_roles(self, host_templates, service):
        custom_roles = set([])
        for role_mapping in host_templates.values():
            if service in role_mapping:
                for custom_role in filter(lambda x: '/' in x, role_mapping[service]):
                    custom_roles.add(custom_role)
        return list(custom_roles)

    def extract_custom_role_groups(self, host_templates):
        custom_role_groups = set([])
        for role_mapping in host_templates.values():
            for (service, roles) in role_mapping.items():
                for custom_role in filter(lambda x: '/' in x, roles):
                    custom_role_groups.add("-".join([service.lower()] + custom_role.split("/")))
        return list(custom_role_groups)
