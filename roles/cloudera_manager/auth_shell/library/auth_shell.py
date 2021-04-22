#!/usr/bin/python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_file, fetch_url, basic_auth_header

import json
import os
import inspect
import tempfile
from ssl import SSLError
import time

try:
    from urllib2 import HTTPRedirectHandler, HTTPError, build_opener, URLError
except ImportError:
    from urllib.request import HTTPRedirectHandler, build_opener
    from urllib.error import HTTPError, URLError


def get_cm_url(module, cm_host, cm_port):
  cm_init_url = 'http://{}:{}'.format(cm_host, cm_port)

  redirect_urls = []

  def no_redirect_opener(store):
    class NoRedirect(HTTPRedirectHandler):
      def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        store.append(newurl)

    return NoRedirect()

  try:
    build_opener(no_redirect_opener(redirect_urls)).open(cm_init_url)

  except HTTPError as e:
    if e.getcode() == 302 and redirect_urls:
      return redirect_urls[0].rstrip('/')
    else:
      module.fail_json(msg='failed to connect to cm', e=e)

  except URLError as e:
    if isinstance(e.reason, SSLError):
      if e.reason.reason == 'CERTIFICATE_VERIFY_FAILED':
        return cm_init_url.rstrip('/')

    module.fail_json(msg='failed to connect to cm', e=e)

  return cm_init_url.rstrip('/')


def ensure_cm_version(module, cm_url, cm_user, cm_pass):
  echo_url = cm_url + '/api/v41/tools/echo'

  headers = { 'Authorization': basic_auth_header(cm_user, cm_pass) }

  resp, info = fetch_url(module, echo_url, headers=headers, method='GET')

  if info['status'] == 404:
    module.fail_json(msg='cm must be 7.1 or above')

  if info['status'] != 200:
    module.fail_json(msg='failed to authenticte with cm', e=info)


def get_cm_kerbose_info(module, cm_url, cm_user, cm_pass):
  kerberos_url = cm_url + '/api/v41/cm/kerberosInfo'

  headers = { 'Authorization': basic_auth_header(cm_user, cm_pass) }

  resp, info = fetch_url(module, kerberos_url, headers=headers, method='GET')

  if info['status'] != 200:
    module.fail_json(msg='failed to retrieve kerberos info from cm', e=info)

  return json.load(resp)


def generate_prinicipal(module, cm_url, cm_user, cm_pass, principal):
  gen_url = cm_url + '/api/v41/cm/commands/generateCredentialsAdhoc'

  headers = {
      'Authorization': basic_auth_header(cm_user, cm_pass),
      'Content-Type': 'application/json'
  }

  data = json.dumps({
    'items': [principal]
  })

  resp, info = fetch_url(module, gen_url, data=data, headers=headers, method='POST')

  if info['status'] != 200:
    module.fail_json(msg='failed to generate principal', e=info)

  command_id = json.load(resp).get('id')

  if not command_id:
    module.fail_json(msg='failed to generate principal – no command id', e=info)

  command_url = cm_url + '/api/v41/commands/' + str(command_id)

  generated = False

  while not generated:
    time.sleep(1)

    resp, info = fetch_url(module, command_url, headers=headers, method='GET')

    if info['status'] != 200:
      module.fail_json(msg='failed to generate principal – command ran', e=info)

    command_details = json.load(resp)

    if command_details.get('success'):
      generated = True

    if not command_details.get('active') and not command_details.get('success'):
      module.fail_json(msg='failed to generate principal – command did not finish', e=info)


def get_cm_keytab(module, cm_url, cm_user, cm_pass, prinicpal):
  keytab_url = cm_url + '/api/v41/cm/retrieveKeytab'

  headers = {
    'Authorization': basic_auth_header(cm_user, cm_pass),
    'Content-Type': 'application/json'
  }

  data = json.dumps({
    'items': [prinicpal]
  })

  old_mask = os.umask(0o277)

  keytab_file = fetch_file(module, keytab_url, data=data, headers=headers, method='POST')

  os.umask(old_mask)

  return keytab_file


def run_module():
  module_args = dict(
    cmd=dict(type='str', required=True),
    cm_host=dict(type='str', required=True),
    cm_port=dict(type='int', required=False, default=7180),
    cm_user=dict(type='str', required=False, default='admin'),
    cm_pass=dict(type='str', required=False, default='admin', no_log=True),
    identity=dict(type='str', required=True),
    host=dict(type='str', required=False),
    fallback=dict(type='str', required=False),
    realm=dict(type='str', required=False),
    set_hadoop_env_on_failure=dict(type='bool', default=True),
    validate_certs=dict(type='bool', default=True)
  )

  module = AnsibleModule(
    argument_spec=module_args,
    supports_check_mode=True
  )

  cmd = module.params['cmd']
  cm_host = module.params['cm_host']
  cm_port = module.params['cm_port']
  cm_user = module.params['cm_user']
  cm_pass = module.params['cm_pass']
  identity = module.params['identity']
  host = module.params['host']
  fallback = module.params['fallback']
  set_hadoop_env_on_failure = module.params['set_hadoop_env_on_failure']

  cm_url = get_cm_url(module, cm_host, cm_port)

  ensure_cm_version(module, cm_url, cm_user, cm_pass)

  cm_kerb_info = get_cm_kerbose_info(module, cm_url, cm_user, cm_pass)

  prelude = ''

  if cm_kerb_info['kerberized']:
    realm = module.params['realm'] or cm_kerb_info['kerberosRealm']

    if host:
      principal = '{}/{}@{}'.format(identity, host, realm)
    else:
      principal = '{}@{}'.format(identity, realm)

    generate_prinicipal(module, cm_url, cm_user, cm_pass, principal)

    cache_file = tempfile.NamedTemporaryFile(dir=module.tmpdir, delete=False)
    module.add_cleanup_file(cache_file.name)

    keytab_locaction = get_cm_keytab(module, cm_url, cm_user, cm_pass, principal)

    prelude = inspect.cleandoc('''
      export KRB5CCNAME=FILE:{}
      export KEYTAB_PRICIPAL={}
      export KEYTAB_LOCATION={}
      kinit -kt $KEYTAB_LOCATION $KEYTAB_PRICIPAL
      trap kdestroy EXIT
    '''.format(cache_file.name, principal, keytab_locaction))

  if set_hadoop_env_on_failure and not cm_kerb_info['kerberized']:
    prelude = 'export HADOOP_USER_NAME={}'.format(fallback or identity)

  if module.check_mode:
    module.exit_json(msg='would execute if not in check mode', cmd=prelude+'\n'+cmd)

  final_cmd = prelude+'\n'+cmd

  rc, out, err = module.run_command(
    args=final_cmd,
    use_unsafe_shell=True
  )

  if rc != 0:
    module.fail_json(msg='rc non-zero [{}]'.format(rc), cmd=final_cmd, rc=rc, stdout=out, stderr=err)

  result = {
    'cmd': final_cmd,
    'changed': True,
    'rc': rc,
    'stdout': out,
    'stderr': err
  }

  module.exit_json(**result)


def main():
  run_module()


if __name__ == '__main__':
  main()
