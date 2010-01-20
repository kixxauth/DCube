#! /usr/bin/env python
import sys
import os

import suites
from tests import test_utils
import httplib
import yaml

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
    temp_test_admin = response.read()
    assert isinstance(temp_test_admin, basestring), \
        'Temp username is not a string ().'% temp_test_admin

  elif checkhost(remote_host):
    host = remote_host

  else:
    raise Exception('no connection to %s or %s'% (localhost, remote_host))

  test_utils.setup(host, (host is localhost), temp_test_admin, passkey)

  suites_ = sys.argv[1:]
  if len(suites_) is 0:
    suites_ = ['full']

  print ''
  print 'Running tests on: %s' % host 
  print 'Running suites: %s' % suites_
  print 'Using admin: %s'% temp_test_admin
  print ''

  suites.run_suites(suites_)

  # If you remove this bit of functionality, I will shoot you.
  cxn = httplib.HTTPConnection(localhost)
  cxn.request('DELETE', '/testsetup')
  response = cxn.getresponse()
  assert response.status == 204, \
      'TEST USER WAS NOT DELETED (http status:%d)'% response.status

if __name__ == '__main__':
  main()
