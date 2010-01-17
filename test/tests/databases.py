import unittest
import tests
import simplejson

URL_USERS = '/users/'
URL_DB = '/databases/'
DB = 'test_db'

def remove_db(aeq, db, username, passkey):
  """Remove a database from the system.
  Args:
    aeq: The assertEqual() method from and instance of unittest.TestCase.
    db: The name of the database to remove.
    username: The username string of the user.
    passkey: The passkey of the user
  
  The privileged 'test_database_admin' must be setup before remove_db will
  work.

  """
  # The first call is just to start the CHAP authentication handshake.
  # Leaving body=None should not be a problem in this call, because the user
  # will not authenticate.
  response = tests.makeRequest(url=(URL_DB + db),
                               method='get',
                               creds=[username],
                               body=None)
  aeq(response['head']['status'], 401)

  response = tests.makeRequest(url=(URL_DB + db),
                               method='delete',
                               creds=tests.createCredentials(
                                 passkey,
                                 *response['head']['authorization']),
                               body=None)
  aeq(response['head']['status'], 204)

  response = tests.makeRequest(url=(URL_DB + db),
                               method='get',
                               creds=tests.createCredentials(
                                 passkey,
                                 *response['head']['authorization']),
                               body=None)
  aeq(response['head']['status'], 404)
  aeq(response['body'], None)

def set_db(aeq, db, username, passkey):
  """Creates a new database in the system.
  Args:
    aeq: The assertEqual() method from and instance of unittest.TestCase.
    db: The name of the database to create.
    username: The username string of the user.
    passkey: The passkey of the user
  
  The privileged 'test_database_admin' must be setup before set_db will
  work.

  """
  # The first call is just to start the CHAP authentication handshake.
  # Leaving body=None should not be a problem in this call, because the user
  # will not authenticate.
  response = tests.makeRequest(url=(URL_DB + db),
                               method='get',
                               creds=[username],
                               body=None)
  aeq(response['head']['status'], 401)

  response = tests.makeRequest(url=(URL_DB + db),
                               method='put',
                               creds=tests.createCredentials(
                                 passkey,
                                 *response['head']['authorization']),
                               body={'name':db, 'whitelist':'*'})

  response = tests.makeRequest(url=(URL_DB + db),
                               method='get',
                               creds=tests.createCredentials(
                                 passkey,
                                 *response['head']['authorization']),
                               body=None)
  aeq(response['head']['status'], 200)
  aeq(response['body'], {'name':db, 'whitelist':'*'})

def set_base_user():
  response = tests.makeRequest(
      url=(URL_USERS + tests.USERNAME),
      method='put',
      creds=[tests.USERNAME])

  assert (response['head']['status'] == 201 or
      response['head']['status'] == 401), \
      ('create user JSONRequest response should be 201 or 401 not %d' %
          response['head']['status'])

def remove_base_user():
  response = tests.makeRequest(
      url=(URL_USERS + tests.USERNAME),
      method='delete',
      creds=[tests.USERNAME])

  assert response['head']['status'] == 401, \
      ('removeUser() JR response status should be 401 not %d' %
          response['head']['status'])

  response = tests.makeRequest(
      url=(URL_USERS + tests.USERNAME),
      method='delete',
      creds=tests.createCredentials(tests.PASSKEY,
      *response['head']['authorization']))

  assert response['head']['status'] == 200, \
      ('removeUser() JR response status should be 200 not %d'%
          response['head']['status'])
  assert response['head']['message'] == ('deleted user "%s"'%
      tests.USERNAME), \
      ('remove user JSONRequest response message should be '
          '(deleted user "%s") not (%s)' %
          (tests.USERNAME, response['head']['message']))

class DatabasesURL(unittest.TestCase):

  def setUp(self):
    set_base_user()

  def tearDown(self):
    remove_base_user()

  def test_method_not_allowed(self):
    """/databases/: method not allowed"""
    cxn = tests.httpConnection()
    cxn.request(*tests.makeJSONRequest_for_httplib(
      url=URL_DB, method='post', creds=[tests.USERNAME]))
    response = cxn.getresponse()
    self.assertEqual(response.status, 200)
    tests.checkHeaders(response.getheaders(),
        tests.defaultHeaders(content_length=False))

    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 405)
    self.assertEqual(json_response['head']['message'], '"POST" method not allowed')
    self.assertEqual(json_response.get('body'), None)

    cxn.close()

  # todo: This test should work with non existing as well an unauthenticated
  # users.
  def test_no_db_url(self):
    """/databases/: db name not included in url"""
    # Authenticate the base user.
    json_response = tests.makeRequest(creds=[tests.USERNAME])

    cxn = tests.httpConnection()
    methods = ['put', 'get', 'delete']

    for m in methods:
      creds = tests.createCredentials(tests.PASSKEY,
        *json_response['head']['authorization'])

      cxn.request(*tests.makeJSONRequest_for_httplib(
        url=URL_DB, method=m, creds=creds))

      response = cxn.getresponse()
      self.assertEqual(response.status, 200)
      tests.checkHeaders(response.getheaders(),
          tests.defaultHeaders(content_length=False))

      json_response = simplejson.loads(response.read())
      self.assertEqual(json_response['head']['status'], 403,
          'method:%s expected:%d got:%d'% (m, 403, json_response['head']['status']))
      self.assertEqual(json_response['head']['message'],
                       'access to url "/databases/" is forbidden')
      self.assertEqual(json_response.get('body'), None)

    cxn.close()

class CreateDatabase(unittest.TestCase):
  """Test a range of user types creating a new DB"""

  local = (tests.HOST is tests.LOCALHOST)
  """Are we on the local dev_appserver?"""

  def setUp(self):
    # Create a new base test user.
    set_base_user()

    # Create the privileged users only if we are testing locally.
    cxn = tests.httpConnection()
    cxn.request('PUT', '/testsetup', None, {'Content-Length':0})
    response = cxn.getresponse()
    self.assertEqual(response.status, 204)
    response.read()
    cxn.close()

    # Remove the test DB.
    remove_db(self.assertEqual, DB, 'test_database_admin', tests.PASSKEY)

  def tearDown(self):
    # Remove the test DB.
    remove_db(self.assertEqual, DB, 'test_database_admin', tests.PASSKEY)

    # Remove the standard test user.
    remove_base_user()

    # Destroy the privileged users only if we are testing locally.
    cxn = tests.httpConnection()
    cxn.request('DELETE', '/testsetup')
    response = cxn.getresponse()
    self.assertEqual(response.status, 204)
    response.read()
    cxn.close()

  def try_create_db(self, username, passkey, priv):
    response = tests.makeRequest(url=(URL_DB + DB),
                                 method='put',
                                 creds=[username],
                                 body=None)
    self.assertEqual(response['head']['status'], 401)
    self.assertEqual(response['body'], None)
    if priv == 'none':
      self.assertEqual(len(response['head']['authorization']), 0)
      return

    response = tests.makeRequest(url=(URL_DB + DB),
                                 method='put',
                                 creds=tests.createCredentials(
                                   passkey,
                                   *response['head']['authorization']),
                                 body={'name':DB, 'whitelist':'*'})
    if priv == 'ok':
      self.assertEqual(response['head']['status'], 201)
      self.assertEqual(response['body'], {'name':DB, 'whitelist':'*'})
    if priv == 'unauth':
      self.assertEqual(response['head']['status'], 401)
      self.assertEqual(response['body'], None)
    if priv == 'forbidden':
      self.assertEqual(response['head']['status'], 403)
      self.assertEqual(response['body'], None)
    else:
      assert False, 'NO TESTS'

    response = tests.makeRequest(url=(URL_DB + DB),
                                 method='get',
                                 creds=tests.createCredentials(
                                   passkey,
                                   *response['head']['authorization']),
                                 body=None)
    if priv == 'ok':
      self.assertEqual(response['head']['status'], 200)
      self.assertEqual(response['body'], {'name':DB, 'whitelist':'*'})
    if priv == 'unauth':
      self.assertEqual(response['head']['status'], 401)
      self.assertEqual(response['body'], None)
    if priv == 'forbidden':
      self.assertEqual(response['head']['status'], 403)
      self.assertEqual(response['body'], None)
    else:
      assert False, 'NO TESTS'

  #
  # todo: test invalid database names
  #
  def test_create_db(self):
    users = [
        ('no_user', 'secret', 'none'),
        (tests.USERNAME, 'incorrect', 'unauth'),
        (tests.USERNAME, tests.PASSKEY, 'forbidden'),
        ('test_sys_admin', tests.PASSKEY, 'forbidden'),
        ('test_user_admin', tests.PASSKEY, 'forbidden'),
        ('test_account_admin', tests.PASSKEY, 'forbidden'),
        ('test_database_admin', tests.PASSKEY, 'ok')]

    for u in users:
      self.try_create_db(*u)

