#! /usr/bin/env python
import os
import sys

import tools
import suites
import tests

def main():
  appconfigs = tools.getconfigs(
      os.path.join(
        os.path.split(
          os.path.split(os.path.abspath(__file__))[0])[0],
        'gae_py'))

  localhost = 'localhost:8080'
  remote_host = (str(appconfigs.get('version')) +'.latest.'+
                 appconfigs.get('application') +'.appspot.com')

  tests.set_LOCALHOST(localhost)
  tests.set_USERNAME('test_user1')
  tests.set_PASSKEY('test$key')

  if tools.checkhost(localhost):
    tests.set_HOST(localhost) 
  elif tools.checkhost(remote_host):
    tests.set_HOST(remote_host) 
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
