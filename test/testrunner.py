#! /usr/bin/env python
import os
import tools
import httplib
import unittest
import simplejson

HOST = None
LOCALHOST = None
REMOTE_HOST = None

URL_USERS = '/users/'

JSONR_HEADERS = {
    'Content-Type':'application/jsonrequest',
    'Accept': 'application/jsonrequest'}

def createJSONRequest(method='get', creds=[], body=None):
  return simplejson.dumps(dict(
      head=dict(method=method, authorization=creds),
      body=body))

def checkHeaders(headers, expected):
  for name, val in headers:
    if expected.get(name) is False:
      continue
    assert (val == expected.get(name)), \
        ('header %s: %s is not %s' % (name, val, expected.get(name)))

class CheckHost(unittest.TestCase):
  def testHost(self):
    """Check for host availability."""
    assert HOST, 'HOST should be defined.'

class RobotsTxt(unittest.TestCase):
  def testRobotsTxt(self):
    """Check for the robots.txt file."""
    user_agent = ('Mozilla/5.0 (compatible; '
           'Googlebot/2.1; +http://www.google.com/bot.html)')

    cxn = httplib.HTTPConnection(HOST)
    cxn.request('GET', '/robots.txt', None, 
        {'User-Agent': user_agent})
    response = cxn.getresponse()

    self.assertEqual(response.status, 200)
    checkHeaders(response.getheaders(),
        {'content-type':'text/plain',
          'content-length':'26',
          'server':(HOST == LOCALHOST and 'Development/1.0' or 'foo'),
          'date': False,
          'cache-control':'no-cache',
          'expires':'-1',})
    
    cxn.close()

class NotFound(unittest.TestCase):
  def testNotFound(self):
    """Check for not found response."""
    cxn = httplib.HTTPConnection(HOST)
    cxn.request('GET', '/foo')
    response = cxn.getresponse()
    self.assertEqual(response.status, 404)
    cxn.close()

class CreateNewUser(unittest.TestCase):
  username = 'test_created_user0'

  # todo check invalid HTTP method

  def test_invalidUsername(self):
    """create new user: username contains invalid characters"""
    cxn = httplib.HTTPConnection(HOST)

    cxn.request('POST', URL_USERS,
        createJSONRequest(method='put', body={'username':'user$invalid '}),
        JSONR_HEADERS)

    response = cxn.getresponse()

    self.assertEqual(response.status, 200)
    checkHeaders(response.getheaders,
        {'content-type':'text/plain', 'content-length':'26'})

    data = simplejson.loads(response.read())

    cxn.close()

  def test_userDoesNotExist(self):
    """create new user: user does not exist -> created"""
    cxn = httplib.HTTPConnection(HOST)

    cxn.request('POST', URL_USERS,
        createJSONRequest(method='put', body={'username':self.username}),
        JSONR_HEADERS)

    response = cxn.getresponse()

    self.assertEqual(response.status, 200)
    checkHeaders(response.getheaders,
        {'content-type':'text/plain', 'content-length':'26'})

    cxn.close()

def main():
  global HOST
  global LOCALHOST
  global REMOTE_HOST

  appconfigs = tools.getconfigs(
      os.path.join(
        os.path.split(
          os.path.split(os.path.abspath(__file__))[0])[0],
        'gae_py'))

  LOCALHOST = 'localhost:8080'
  REMOTE_HOST = (str(appconfigs.get('version')) +'.latest.'+
                 appconfigs.get('application') +'.appspot.com')

  if tools.checkhost(LOCALHOST):
    HOST = LOCALHOST 
  elif tools.checkhost(remotehost):
    HOST = REMOTE_HOST 
  else:
    raise Exception('no connection to %s or %s'% (LOCALHOST, REMOTE_HOST))

  print 'running tests on %s' % HOST
  print

  unittest.main()

if __name__ == '__main__':
  main()
