#! /usr/bin/env python
import unittest

import os
import sys
import httplib
import simplejson

import tools
import suites
import tests

HOST = None
LOCALHOST = None
REMOTE_HOST = None

URL_USERS = '/users/'

TEST_USER = 'test_created_user0'
TEST_PASSKEY = 'pk'

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

def removeUser(username, passkey):
  cxn = httplib.HTTPConnection(HOST)
  cxn.request('POST', URL_USERS + username,
      createJSONRequest(method='delete',
                        creds=[username]),
                        JSONR_HEADERS)
  response = cxn.getresponse()
  json_response = simplejson.loads(response.read())

  # user does not exist
  if len(json_response['head']['authorization']) < 3:
    return

  assert json_response['head']['status'] == 401, \
      ('removeUser() JR response status should be 401 not %d' %
          json_response['head']['status'])

  creds = tools.createCredentials(passkey,
                                  *json_response['head']['authorization'])

  cxn.request('POST',
              URL_USERS + username,
              createJSONRequest(method='delete', creds=creds),
              JSONR_HEADERS)
  response = cxn.getresponse()
  json_response = simplejson.loads(response.read())
  cxn.close()
  assert json_response['head']['status'] == 200, \
      ('removeUser() JR response status should be 200 not %d' %
          json_response['head']['status'])
  assert json_response['head']['message'] == ('deleted user "%s"' % username), \
      ('remove user JSONRequest response message should be '
          '(deleted user "%s") not (%s)' %
          (username, json_response['head']['message']))

def createUser(username):
  cxn = httplib.HTTPConnection(HOST)
  cxn.request('POST', URL_USERS + username,
      createJSONRequest(method='put', creds=[username]),
      JSONR_HEADERS)

  response = cxn.getresponse()
  assert response.status is 200, 'create user http response should be 200'

  json_response = simplejson.loads(response.read())
  cxn.close()
  assert (json_response['head']['status'] == 201 or
      json_response['head']['status'] == 401), \
      ('create user JSONRequest response should be 201 or 401 not %d' %
          json_response['head']['status'])
  return (json_response['head']['authorization'][1],
      json_response['head']['authorization'][2])

class UsersURL(unittest.TestCase):
  def test_methodNotAllowed(self):
    """/users/: method not allowed"""
    cxn = httplib.HTTPConnection(HOST)

    cxn.request('POST', URL_USERS,
        createJSONRequest(method='post', creds=['foo_user']),
        JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)

    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 405)
    self.assertEqual(json_response['head']['message'], '"POST" method not allowed')
    self.assertEqual(json_response.get('body'), None)

    cxn.close()

  def test_noUserURL(self):
    """/users/: username not included in url"""
    cxn = httplib.HTTPConnection(HOST)

    #put
    cxn.request('POST', URL_USERS,
        createJSONRequest(method='put', creds=[self.username]),
        JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)

    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 403)
    self.assertEqual(json_response['head']['message'],
                     'access to url "/users/" is forbidden')
    self.assertEqual(json_response.get('body'), None)

    #get
    cxn.request('POST', URL_USERS,
        createJSONRequest(method='get', creds=[self.username]),
        JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)

    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 403)
    self.assertEqual(json_response['head']['message'],
                     'access to url "/users/" is forbidden')
    self.assertEqual(json_response.get('body'), None)

    #delete
    cxn.request('POST', URL_USERS,
        createJSONRequest(method='delete', creds=[self.username]),
        JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)

    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 403)
    self.assertEqual(json_response['head']['message'],
                     'access to url "/users/" is forbidden')
    self.assertEqual(json_response.get('body'), None)

    cxn.close()

  def test_usernameNotMatch(self):
    """/users/: username does not match url"""
    cxn = httplib.HTTPConnection(HOST)

    cxn.request('POST', URL_USERS +'foo_bar',
        createJSONRequest(method='put', creds=[self.username]),
        JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)

    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 400)
    self.assertEqual(json_response['head']['message'],
                     ('username "%s" does not match url "/users/foo_bar"' %
                       self.username))
    self.assertEqual(json_response.get('body'), None)

    cxn.request('POST', URL_USERS +'foo_bar',
        createJSONRequest(method='get', creds=[self.username]),
        JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)

    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 400)
    self.assertEqual(json_response['head']['message'],
                     ('username "%s" does not match url "/users/foo_bar"' %
                       self.username))
    self.assertEqual(json_response.get('body'), None)

    cxn.request('POST', URL_USERS +'foo_bar',
        createJSONRequest(method='delete', creds=[self.username]),
        JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)

    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 400)
    self.assertEqual(json_response['head']['message'],
                     ('username "%s" does not match url "/users/foo_bar"' %
                       self.username))
    self.assertEqual(json_response.get('body'), None)

    cxn.close()

class ExistingUser(unittest.TestCase):
  username = TEST_USER
  passkey = TEST_PASSKEY

  def setUp(self):
    self.nonce, self.nextnonce = createUser(self.username)

  def tearDown(self):
    removeUser(self.username, self.passkey)

  def test_getUser(self):
    """Try to get a user with no creds."""
    cxn = httplib.HTTPConnection(HOST)
    cxn.request('POST',
                URL_USERS + self.username,
                createJSONRequest(method='get',
                                  creds=[self.username]),
                JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)
    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 401)

    creds = tools.createCredentials(self.passkey,
                                    *json_response['head']['authorization'])

    cxn.request('POST',
                URL_USERS + self.username,
                createJSONRequest(method='get', creds=creds),
                JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)
    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 200)
    self.assertEqual(json_response.get('body'),
                     {'username': self.username, 'groups': ['users']})

    cxn.close()

  def test_putUser(self):
    """Put a user that already exists."""
    cxn = httplib.HTTPConnection(HOST)
    cxn.request('POST',
                URL_USERS + self.username,
                createJSONRequest(method='put',
                                  creds=[self.username]),
                JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)
    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 401)

    creds = tools.createCredentials(self.passkey,
                                    *json_response['head']['authorization'])

    cxn.request('POST',
                URL_USERS + self.username,
                createJSONRequest(method='put', creds=creds),
                JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)
    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 200)
    self.assertEqual(json_response.get('body'),
                     {'username': self.username, 'groups': ['users']})

    cxn.close()

  def test_deleteUser(self):
    """Delete a user"""
    creds = tools.createCredentials(
        self.passkey, self.username, self.nonce, self.nextnonce)
    cxn = httplib.HTTPConnection(HOST)
    cxn.request('POST', URL_USERS + self.username,
        createJSONRequest(method='delete',
                          creds=creds),
                          JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)

    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 200)
    self.assertEqual(json_response['head']['message'], 'deleted user "%s"' % self.username)
    self.assertEqual(len(json_response['head']['authorization']), 0)
    self.assertEqual(json_response.get('body'), None)

    cxn.close()

class NoUser(unittest.TestCase):
  username = TEST_USER
  passkey = TEST_PASSKEY

  def setUp(self):
    """Delete the test user to setUp the create user test."""
    removeUser(self.username, self.passkey)

  def test_createUser(self):
    """create new user: user does not exist -> created"""
    cxn = httplib.HTTPConnection(HOST)

    cxn.request('POST', URL_USERS + self.username,
        createJSONRequest(method='put', creds=[self.username]),
        JSONR_HEADERS)

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)

    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 201)
    self.assertEqual(json_response['head']['message'],
        'created new user "'+ self.username +'"')
    self.assertEqual(json_response['head']['authorization'][0], self.username)
    self.assertEqual(len(json_response['head']['authorization'][1]), 40)
    self.assertEqual(len(json_response['head']['authorization'][2]), 40)
    self.assertEqual(json_response.get('body'),
                     {'username': self.username, 'groups': ['users']})

    cxn.close()

  def test_getUser(self):
    """Try getting a non existing user."""
    cxn = httplib.HTTPConnection(HOST)
    cxn.request('POST', URL_USERS + self.username,
        createJSONRequest(method='get',
                          creds=[self.username]),
                          JSONR_HEADERS)
    response = cxn.getresponse()
    json_response = simplejson.loads(response.read())
    cxn.close()

    self.assertEqual(json_response['head']['status'], 404)
    self.assertEqual(json_response['head']['message'],
                     'user "%s" not found' % self.username)
    self.assertEqual(len(json_response['head']['authorization']), 0)

  def test_deleteUser(self):
    """Delete the non existing test user."""
    cxn = httplib.HTTPConnection(HOST)
    cxn.request('POST', URL_USERS + self.username,
        createJSONRequest(method='delete',
                          creds=[self.username]),
                          JSONR_HEADERS)
    response = cxn.getresponse()
    json_response = simplejson.loads(response.read())
    cxn.close()

    self.assertEqual(json_response['head']['status'], 200)
    self.assertEqual(json_response['head']['message'], 'deleted user "%s"' % self.username)
    self.assertEqual(len(json_response['head']['authorization']), 0)

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

  if tools.checkhost(localhost):
    tests.set_HOST(localhost) 
  elif tools.checkhost(remote_host):
    tests.set_HOST(remote_host) 
  else:
    raise Exception('no connection to %s or %s'% (localhost, remote_host))

  print ''
  print 'running tests on %s' % tests.HOST
  print ''

  #unittest.main()
  suites.run_suites(['full'])

if __name__ == '__main__':
  main()
