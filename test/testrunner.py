#! /usr/bin/env python
import sys
import os
import httplib
import simplejson
import yaml

import suites
from tests import test_utils
from tests import teardown

def checkhost(url):
  cxn = httplib.HTTPConnection(url)
  try:
    cxn.request('GET', '/')
    return True
  except httplib.socket.error:
    return False

def getconfigs(dir):
  """Takes the path to the root app directory and returns the current app
  configs as parsed by PyYaml.
  """
  return yaml.load(open(os.path.join(dir, 'app.yaml')))

def make_auth_request(host, username, passkey=None, nonce=None, nextnonce=None):
  if nonce is None or nextnonce is None or passkey is None:
    creds = '["%s"]'% username
  else:
    creds = simplejson.dumps(
        test_utils.create_credentials(
          passkey, username, nonce, nextnonce))

  body = '{"head":{"method":"get", "authorization":%s}}'% creds
  
  cxn = httplib.HTTPConnection(host)
  cxn.request('POST', '/', body, {
        'User-Agent': 'UA:DCube test :: Auth sys-admin',
        'Content-Length': str(len(body)),
        'Accept': 'application/jsonrequest',
        'Content-Type': 'application/jsonrequest'})
  response = cxn.getresponse()
  response_body = response.read()
  cxn.close()

  assert response.status is 200, \
      'Unexpected HTTP status code (%d) on login.'% response.status
  json = simplejson.loads(response_body)

  len_auth = len(json['head']['authorization'])
  if len_auth < 1:
    return False, None, None, None

  if len_auth is 3:
    auth = json['head']['status'] is 200 and True or False
    nonce = json['head']['authorization'][1]
    nextnonce = json['head']['authorization'][2]
    return auth, username, nonce, nextnonce

  return False, username, None, None

def prompt_username():
  un = raw_input('sys-admin username: ')
  if len(un) < 1:
    print 'username must be more than 0 characters'
    return prompt_username()
  return un

def prompt_passkey(username):
  import getpass
  pk = getpass.getpass('passkey for %s: '% username)
  if len(pk) < 1:
    print 'passkey must be more than 0 characters'
    return prompt_passkey()
  return pk

def authenticate(host):
  username = prompt_username()
  auth, username_, nonce, nextnonce = make_auth_request(host, username)
  if username_ is None:
    return None, None

  assert nonce and nextnonce, 'Missing nonce or nextnonce.'
  passkey = prompt_passkey(username)
  auth, username_, nonce, nextnonce = \
      make_auth_request(host, username, passkey, nonce, nextnonce)

  if not auth:
    return username, None

  return username, passkey

def main():
  localhost = 'localhost:8080'
  passkey = 'secret$key'

  appconfigs = getconfigs(
      os.path.join(
        os.path.split(
          os.path.split(os.path.abspath(__file__))[0])[0],
        'gae_py'))

  remote_host = (str(appconfigs.get('version')) +'.latest.'+
                 appconfigs.get('application') +'.appspot.com')

  if checkhost(localhost):
    host = localhost
    cxn = httplib.HTTPConnection(localhost)
    cxn.request('PUT', '/testsetup', None, {'Content-Length':0})
    response = cxn.getresponse()
    assert response.status == 200, \
        'Test user was not setup (status: %d)'% response.status
    temp_test_admin = response.read().rstrip()
    assert isinstance(temp_test_admin, basestring), \
        'Temp username is not a string ().'% temp_test_admin

  elif checkhost(remote_host):
    host = remote_host
    temp_test_admin, passkey = authenticate(host)
    if temp_test_admin is None:
      print 'User does not exist.'
      exit()
    if passkey is None:
      print 'Invalid passkey... exit()'
      exit()

  else:
    raise Exception('no connection to %s or %s'% (localhost, remote_host))

  test_utils.setup(host, (host is localhost), temp_test_admin, passkey)

  suites_ = sys.argv[1:]
  if len(suites_) is 0:
    suites_ = ['full']

  print ''
  print 'Running tests on: %s' % host 
  print 'Running suites: %s' % suites_
  print 'Using admin account for: %s'% temp_test_admin
  print ''

  suites.run_suites(suites_)

  # Teardown insecure user created for testing.
  teardown.teardown()
  # If you remove this bit of functionality, I will shoot you.

  if host is localhost:
    # Teardown local sys_admin user.
    cxn = httplib.HTTPConnection(localhost)
    cxn.request('DELETE', '/testsetup')
    response = cxn.getresponse()
    assert response.status == 204, \
        'TEST USER WAS NOT DELETED (http status:%d)'% response.status

if __name__ == '__main__':
  main()
