import unittest
import tests
import simplejson

URL_USERS = '/users/'
URL_DB = '/databases/'

class CreateDatabase(unittest.TestCase):
  """Test a range of user types creating a new DB"""
  def setUp(self):
    response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='put', creds=[tests.USERNAME])

    assert (response['head']['status'] == 201 or
        response['head']['status'] == 401), \
        ('create user JSONRequest response should be 201 or 401 not %d' %
            response['head']['status'])

  def tearDown(self):
    response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='delete', creds=[tests.USERNAME])

    # user does not exist
    if len(response['head']['authorization']) < 3:
      return

    assert response['head']['status'] == 401, \
        ('removeUser() JR response status should be 401 not %d' %
            response['head']['status'])

    creds = tests.createCredentials(tests.PASSKEY,
        *response['head']['authorization'])

    response = tests.makeRequest(
        url=(URL_USERS + tests.USERNAME), method='delete', creds=creds)

    assert response['head']['status'] == 200, \
        ('removeUser() JR response status should be 200 not %d' %
            response['head']['status'])
    assert response['head']['message'] == ('deleted user "%s"' % tests.USERNAME), \
        ('remove user JSONRequest response message should be '
            '(deleted user "%s") not (%s)' %
            (tests.USERNAME, response['head']['message']))

  def test_create_db(self):
    users = [
        (tests.USERNAME, 'sys_admin'),
        ('test_sys_admin', 'sys_admin'),
        ('test_user_admin', 'user_admin'),
        ('test_account_admin', 'account_admin'),
        ('test_database_admin', 'database')]
