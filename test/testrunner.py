#! /usr/bin/env python
import os
import sys

import suites
import tests # todo: remove
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
  appconfigs = getconfigs(
      os.path.join(
        os.path.split(
          os.path.split(os.path.abspath(__file__))[0])[0],
        'gae_py'))

  localhost = 'localhost:8080'
  remote_host = (str(appconfigs.get('version')) +'.latest.'+
                 appconfigs.get('application') +'.appspot.com')

  tests.set_LOCALHOST(localhost) # todo: remove
  tests.set_USERNAME('test_user1') # todo: remove
  tests.set_PASSKEY('test$key') # todo: remove

  if checkhost(localhost):
    tests.set_HOST(localhost) # todo: remove
    test_utils.setup(localhost)
  elif checkhost(remote_host):
    tests.set_HOST(remote_host) # todo: remove
    test_utils.setup(remote_host)
  else:
    raise Exception('no connection to %s or %s'% (localhost, remote_host))

  suites_ = sys.argv[1:]
  if len(suites_) is 0:
    suites_ = ['full']

  print ''
  print 'running tests on %s' % tests.HOST
  print 'running suites %s' % suites_
  print ''

  suites.run_suites(suites_)

if __name__ == '__main__':
  main()
