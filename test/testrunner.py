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

  if checkhost(localhost):
    host = localhost

  else:
    appconfigs = getconfigs(
        os.path.join(
          os.path.split(
            os.path.split(os.path.abspath(__file__))[0])[0],
          'gae_py'))

    remote_host = (str(appconfigs.get('version')) +'.latest.'+
                   appconfigs.get('application') +'.appspot.com')

    if checkhost(remote_host):
      host = remote_host
    else:
      raise Exception('no connection to %s or %s'% (localhost, remote_host))

  test_utils.setup(host, (host is localhost))

  suites_ = sys.argv[1:]
  if len(suites_) is 0:
    suites_ = ['full']

  print ''
  print 'running tests on %s' % host 
  print 'running suites %s' % suites_
  print ''

  suites.run_suites(suites_)

if __name__ == '__main__':
  main()
