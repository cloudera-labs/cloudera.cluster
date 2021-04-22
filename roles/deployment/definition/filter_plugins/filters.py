#!/usr/bin/python
# Copyright 2021 Cloudera, Inc.
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
import re

class FilterModule(object):

  def filters(self):
    return {
        'extract_products_from_manifests': self.extract_products_from_manifests,
        'format_database_type': self.format_database_type,
        'get_product_version': self.get_product_version,
        'get_major_version': self.get_major_version,
        'append_database_port': self.append_database_port,
        'default_database_port': self.default_database_port,
        'get_database_encoding_mysql': self.get_database_encoding_mysql,
        'get_database_collation_mysql': self.get_database_collation_mysql,
        'cluster_service_role_hosts': self.cluster_service_role_hosts,
        'find_clusters': self.find_clusters
    }


  def extract_products_from_manifests(self, manifests):
    products = dict()
    for manifest in manifests:
      for parcel in manifest['parcels']:
        # take first parcel, strip off OS name and file extension
        parcel_name = re.sub("-[a-z0-9]+\.parcel$", "", str(parcel['parcelName']))
        # the product name is before the first dash
        product = parcel_name[:parcel_name.index("-")]
        if product not in products:
          # the version string is everything after the first dash
          version = parcel_name[parcel_name.index("-")+1:]
          products[product] = version
    return products


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
