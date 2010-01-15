import unittest
import tests
import simplejson

URL_USERS = '/users/'

def removeUser(username, passkey):
  json_response = tests.makeRequest(
      url=(URL_USERS + username), method='delete', creds=[username])

  # user does not exist
  if len(json_response['head']['authorization']) < 3:
    return

  assert json_response['head']['status'] == 401, \
      ('removeUser() JR response status should be 401 not %d' %
          json_response['head']['status'])

  creds = tests.createCredentials(passkey,
      *json_response['head']['authorization'])

  json_response = tests.makeRequest(
      url=(URL_USERS + username), method='delete', creds=creds)

  assert json_response['head']['status'] == 200, \
      ('removeUser() JR response status should be 200 not %d' %
          json_response['head']['status'])
  assert json_response['head']['message'] == ('deleted user "%s"' % username), \
      ('remove user JSONRequest response message should be '
          '(deleted user "%s") not (%s)' %
          (username, json_response['head']['message']))

def createUser(username):
  json_response = tests.makeRequest(
      url=(URL_USERS + username), method='put', creds=[username])

  assert (json_response['head']['status'] == 201 or
      json_response['head']['status'] == 401), \
      ('create user JSONRequest response should be 201 or 401 not %d' %
          json_response['head']['status'])
  return (json_response['head']['authorization'][1],
      json_response['head']['authorization'][2])

class UsersURL(unittest.TestCase):
  def test_methodNotAllowed(self):
    """/users/: method not allowed"""
    cxn = tests.httpConnection()
    cxn.request(*tests.makeJSONRequest_for_httplib(
      url=URL_USERS, method='post', creds=[tests.USERNAME]))

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)
    tests.checkHeaders(response.getheaders(),
        tests.defaultHeaders(content_length=False))

    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 405)
    self.assertEqual(json_response['head']['message'], '"POST" method not allowed')
    self.assertEqual(json_response.get('body'), None)

    cxn.close()

  def test_noUserURL(self):
    """/users/: username not included in url"""
    cxn = tests.httpConnection()
    methods = ['put', 'get', 'delete']

    for m in methods:
      cxn.request(*tests.makeJSONRequest_for_httplib(
        url=URL_USERS, method=m, creds=[tests.USERNAME]))

      response = cxn.getresponse()
      self.assertEqual(response.status, 200)
      tests.checkHeaders(response.getheaders(),
          tests.defaultHeaders(content_length=False))

      json_response = simplejson.loads(response.read())
      self.assertEqual(json_response['head']['status'], 403)
      self.assertEqual(json_response['head']['message'],
                       'access to url "/users/" is forbidden')
      self.assertEqual(json_response.get('body'), None)

    cxn.close()

class ExistingUser(unittest.TestCase):
  def setUp(self):
    self.nonce, self.nextnonce = createUser(tests.USERNAME)

  def tearDown(self):
    removeUser(tests.USERNAME, tests.PASSKEY)

  def test_getUser(self):
    """GET a user that exists."""
    json_response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='get', creds=[tests.USERNAME])

    self.assertEqual(json_response['head']['status'], 401)
    self.assertEqual(json_response['head']['message'], 'authenticate')
    self.assertEqual(json_response.get('body'), None)

    creds = tests.createCredentials(tests.PASSKEY,
        *json_response['head']['authorization'])

    json_response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='get', creds=creds)

    self.assertEqual(json_response['head']['status'], 200)
    self.assertEqual(json_response.get('body'),
        {'username': tests.USERNAME, 'groups': ['users']})

  def test_putUser(self):
    """PUT a user that already exists."""
    json_response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='put', creds=[tests.USERNAME])

    self.assertEqual(json_response['head']['status'], 401)
    self.assertEqual(json_response['head']['message'], 'authenticate')
    self.assertEqual(json_response.get('body'), None)

    creds = tests.createCredentials(tests.PASSKEY,
        *json_response['head']['authorization'])
    json_response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='put', creds=creds)

    # a null user data body will result in a 400
    self.assertEqual(json_response['head']['status'], 400)
    self.assertEqual(json_response['head']['message'], 'invalid user data')

    creds = tests.createCredentials(tests.PASSKEY,
        *json_response['head']['authorization'])
    json_response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='put', creds=creds,
        body={'username':'x'})

    # a missing groups declaration will result in a 400
    self.assertEqual(json_response['head']['status'], 400)
    self.assertEqual(json_response['head']['message'],
        'user data must include a groups list')

    creds = tests.createCredentials(tests.PASSKEY,
        *json_response['head']['authorization'])
    json_response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='put', creds=creds,
        body={'groups':'x'})

    # a missing username declaration will result in a 400
    self.assertEqual(json_response['head']['status'], 400)
    self.assertEqual(json_response['head']['message'],
        'user data must include a username')

    creds = tests.createCredentials(tests.PASSKEY,
        *json_response['head']['authorization'])
    json_response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='put', creds=creds,
        body={'username':tests.USERNAME,'groups':['users']})

    # a correct data will result in a 200
    self.assertEqual(json_response['head']['status'], 200)
    self.assertEqual(json_response['head']['message'],
        'updated user "%s"' % tests.USERNAME)

  def test_deleteUser(self):
    """DELETE a user that already exists"""
    json_response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='delete', creds=[tests.USERNAME])

    self.assertEqual(json_response['head']['status'], 401)
    self.assertEqual(json_response['head']['message'], 'authenticate')
    self.assertEqual(json_response.get('body'), None)

    creds = tests.createCredentials(tests.PASSKEY,
        *json_response['head']['authorization'])

    json_response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='get', creds=creds)

    self.assertEqual(json_response['head']['status'], 200)
    self.assertEqual(json_response.get('body'),
        {'username': tests.USERNAME, 'groups': ['users']})

class NoUser(unittest.TestCase):
  def setUp(self):
    """Delete the test user to setUp the create user test."""
    removeUser(tests.USERNAME, tests.PASSKEY)

  def test_putUser(self):
    """PUT a new user"""
    json_response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='put', creds=[tests.USERNAME])

    self.assertEqual(json_response['head']['status'], 201)
    self.assertEqual(json_response['head']['message'],
        'created new user "%s"'% tests.USERNAME)
    self.assertEqual(json_response['head']['authorization'][0], tests.USERNAME)
    self.assertEqual(len(json_response['head']['authorization'][1]), 40)
    self.assertEqual(len(json_response['head']['authorization'][2]), 40)
    self.assertEqual(json_response.get('body'),
        {'username': tests.USERNAME, 'groups': ['users']})

  def test_getUser(self):
    """GET a non existing user."""
    json_response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='get', creds=[tests.USERNAME])

    self.assertEqual(json_response['head']['status'], 404)
    self.assertEqual(json_response['head']['message'],
        'user "%s" not found'% tests.USERNAME)
    self.assertEqual(json_response['head']['authorization'], [])
    self.assertEqual(json_response.get('body'), None)

  def test_deleteUser(self):
    """DELETE the non existing test user."""
    json_response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='delete', creds=[tests.USERNAME])

    self.assertEqual(json_response['head']['status'], 200)
    self.assertEqual(json_response['head']['message'],
        'deleted user "%s"'% tests.USERNAME)
    self.assertEqual(json_response['head']['authorization'], [])
    self.assertEqual(json_response.get('body'), None)

class PrivUsers_BaseUser(unittest.TestCase):
  def setUp(self):
    createUser(tests.USERNAME)

  def tearDown(self):
    removeUser(tests.USERNAME, tests.PASSKEY)

  def test_sys_admin(self):
    """sys_admin updates base test_user"""
    passkey = 'secret_passkey'
    username = 'test_sys_admin'

    # authenticate by calling the root domain url
    json_response = tests.makeRequest(method='get', creds=[username])
    creds = tests.createCredentials(passkey,
        *json_response['head']['authorization'])

    # get the base user
    json_response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='get', creds=creds)
    target_user = json_response['body']
    self.assertEqual(target_user.get('groups'), ['users'])

    # modify the group
    target_user['groups'] = ['users','database']
    creds = tests.createCredentials(passkey,
        *json_response['head']['authorization'])
    json_response = tests.makeRequest(url=(URL_USERS + tests.USERNAME),
        method='put', creds=creds, body=target_user)

    self.assertEqual(json_response['head']['status'], 200)
    self.assertEqual(json_response.get('body'),
        {'username': tests.USERNAME, 'groups': ['users','database']})

    # get it back
    creds = tests.createCredentials(passkey,
        *json_response['head']['authorization'])
    json_response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='get', creds=creds)
    self.assertEqual(json_response['body'].get('groups'), ['users','database'])

