#! /usr/bin/env python
import os
import tools
import unittest

HOST = None

class CheckHost(unittest.TestCase):
  def testHost(self):
    """Check for host availability."""
    assert HOST, 'HOST should be defined.'

def main():
  global HOST

  appconfigs = tools.getconfigs(
      os.path.join(
        os.path.split(
          os.path.split(os.path.abspath(__file__))[0])[0],
        'gae_py'))

  localhost = 'localhost:8080'
  remotehost = (str(appconfigs.get('version')) +'.latest.'+
                 appconfigs.get('application') +'.appspot.com')

  if tools.checkhost(localhost):
    HOST = localhost 
  elif tools.checkhost(remotehost):
    HOST = remotehost 
  else:
    raise Exception('no connection to %s or %s'% (localhost, remotehost))

  print 'running tests on %s' % HOST
  print

  unittest.main()

if __name__ == '__main__':
  main()
