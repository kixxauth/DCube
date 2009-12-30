#! /usr/bin/env python
import os
import sys
import tools
import httplib
import unittest
import simplejson

HOST = None
LOCALHOST = None
REMOTE_HOST = None

URL_USERS = '/users/'

JSONR_HEADERS = {
    'Content-Type': 'application/jsonrequest',
    'Accept': 'application/jsonrequest',
    'User-Agent': 'testing_client'}

def defaultHeaders(content_length='0',
                   content_type='application/jsonrequest',
                   cache_control='no-cache',
                   expires='-1'):
  return {'content-type': content_type,
          'content-length': content_length,
          'server':(HOST == LOCALHOST and 'Development/1.0' or 'foo'),
          'date': False,
          'cache-control': cache_control,
          'expires': expires}

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
        defaultHeaders(content_length='26',
                       content_type='text/plain'))
    
    cxn.close()

class NotFound(unittest.TestCase):
  def testNotFound(self):
    """Check for not found response."""
    cxn = httplib.HTTPConnection(HOST)
    cxn.request('GET', '/foo')
    response = cxn.getresponse()
    self.assertEqual(response.status, 404)
    cxn.close()

class UsersURL(unittest.TestCase):
  def setUp(self):
    global JSONR_HEADERS
    JSONR_HEADERS = {
        'Content-Type': 'application/jsonrequest',
        'Accept': 'application/jsonrequest',
        'User-Agent': 'testing_client'}

  def test_invalidURL(self):
    """invalid users url"""
    cxn = httplib.HTTPConnection(HOST)
    cxn.request('GET', '/users')
    self.assertEqual(cxn.getresponse().status, 404)
    cxn.close()

  def test_invalidMethod(self):
    """/users/: invalid http method PUT"""
    cxn = httplib.HTTPConnection(HOST)
    cxn.request('PUT', URL_USERS, 'body to put')
    self.assertEqual(cxn.getresponse().status, 405)

  def test_invalidContentTypeHeader(self):
    """/users/: invalid content type header"""
    cxn = httplib.HTTPConnection(HOST)
    content_type = 'application/x-www-form-urlencoded'
    headers = JSONR_HEADERS
    headers['Content-Type'] = content_type
    cxn.request('GET', URL_USERS, None, headers)
    response = cxn.getresponse()
    self.assertEqual(response.status, 400)
    self.assertEqual(response.read(),
        ('invalid JSONRequest Content-Type %s from user agent %s' % \
            (content_type, JSONR_HEADERS['User-Agent'])))
    cxn.close()

  def test_invalidAcceptHeader(self):
    """/users/: invalid accept header"""
    cxn = httplib.HTTPConnection(HOST)
    accept = 'text/html'
    headers = JSONR_HEADERS
    headers['Accept'] = accept 
    cxn.request('POST', URL_USERS, None, headers)
    self.assertEqual(cxn.getresponse().status, 406)
    cxn.close()

  def test_invalidJSONRequestBody(self):
    """/users/: invalid JSONRequest body"""
    invalid_json = '{not valid json}'
    cxn = httplib.HTTPConnection(HOST)
    cxn.request('POST', URL_USERS, invalid_json, JSONR_HEADERS)
    response = cxn.getresponse()
    self.assertEqual(response.status, 400)
    self.assertEqual(response.read(),
        'invalid JSONRequest body from user agent %s' %
            JSONR_HEADERS['User-Agent'])

    cxn.close()

  def test_invalidJSONRequestBodyAsArray(self):
    """/users/: invalid JSONRequest body as array"""
    invalid_json = '[1,2,3]'
    cxn = httplib.HTTPConnection(HOST)

    cxn.request('POST', URL_USERS, invalid_json, JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)

    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 400)
    self.assertEqual(json_response['head']['message'], 'invalid JSON body')
    self.assertEqual(json_response.get('body'), None)

    cxn.close()

  def test_noAuthCreds(self):
    """/users/: no user authentication creds"""
    cxn = httplib.HTTPConnection(HOST)

    cxn.request('POST', URL_USERS,
        createJSONRequest(method='put'),
        JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)

    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 401)
    self.assertEqual(json_response['head']['message'], 'credentials required')
    self.assertEqual(json_response.get('body'), None)

    cxn.close()

  def test_invalidUsername(self):
    """/users/: invalid username authentication creds"""
    cxn = httplib.HTTPConnection(HOST)

    cxn.request('GET', URL_USERS,
        createJSONRequest(method='get', creds=[None]),
        JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)

    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 401)
    self.assertEqual(json_response['head']['message'], 'invalid username "None"')
    self.assertEqual(json_response.get('body'), None)

    cxn.close()

class CreateNewUser(unittest.TestCase):
  username = 'test_created_user0'

  def test_invalidUsername(self):
    """create new user: username contains invalid characters"""
    invalid_username = 'user$invalid '

    cxn = httplib.HTTPConnection(HOST)

    cxn.request('GET', URL_USERS,
        createJSONRequest(method='get', creds=[invalid_username]),
        JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)

    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 401)
    self.assertEqual(json_response['head']['message'],
                     'invalid username "'+ invalid_username +'"')
    self.assertEqual(json_response.get('body'), None)

    cxn.close()

  def test_userDoesNotExist(self):
    """create new user: user does not exist -> created"""
    cxn = httplib.HTTPConnection(HOST)
    cxn.request('POST', URL_USERS,
        createJSONRequest(method='put', body={'username':self.username}),
        JSONR_HEADERS)

    response = cxn.getresponse()

    self.assertEqual(response.status, 200)
    checkHeaders(response.getheaders(),
        defaultHeaders(content_length='94'))

    data = simplejson.loads(response.read())
    head = data.get('head')
    assert head.get('status') == 201, \
        'created new user should return status 201'
    assert head.get('authorization') == [], \
        'created new user should return authorization []'
    assert data.get('body') == ('created user '+ self.username), \
        'username should be returned as the body message'

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
  elif tools.checkhost(REMOTE_HOST):
    HOST = REMOTE_HOST 
  else:
    raise Exception('no connection to %s or %s'% (LOCALHOST, REMOTE_HOST))

  print 'running tests on %s' % HOST
  print

  unittest.main()

if __name__ == '__main__':
  main()
