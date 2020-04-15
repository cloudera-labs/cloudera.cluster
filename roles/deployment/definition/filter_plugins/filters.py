#!/usr/bin/python

import json

class FilterModule(object):

  def filters(self):
    return {
        'extract_products_from_manifests': self.extract_products_from_manifests,
        'format_database_type': self.format_database_type,
        'get_product_version': self.get_product_version,
        'append_database_port': self.append_database_port,
        'default_database_port': self.default_database_port
    }

  def extract_products_from_manifests(self, manifests):
      products = list()
      for manifest in manifests:
        parcel = manifest['parcels'][0]
        parcel_file_name = str(parcel['parcelName'])
        parcel_name_parts = parcel_file_name.replace('.parcel','').split("-")
        product = parcel_name_parts[0]
        version = parcel_name_parts[1] + "-" + parcel_name_parts[2]
        products.append({"product": product, "version": version})
      return products

  def format_database_type(self, database_type, service_type=None):
    if service_type and service_type.upper()  == "RANGER":
      # allowed values: MySQL,Oracle,PostgreSQL,MsSQL,SQLA
      if database_type == "mysql" or database_type == "mariadb":
        return "MySQL"
      elif database_type == "postgresql":
        return "PostgreSQL"
      elif database_type == "oracle":
        return "Oracle"
      else:
        return "Unknown"
    else:
      if database_type == "mariadb":
        return "mysql"
      return database_type.lower()

  def get_product_version(self, products, product_name):
    for product in products:
      if product['product'] == product_name:
        version = product['version']
        return version[:version.index('-')] if "-" in version else version

  def append_database_port(self, database_host, database_port=None):
    if ":" not in database_host and database_port:
      return database_host + ":" + database_port
    return database_host

  def default_database_port(self, database_type):
    if database_type == "postgresql":
      return 5432
    if database_type == "mysql" or database_type == "mariadb":
      return 3306
    return None
