"""
  tests.teardown
  ~~~~~~~~~~~~~~

  Utilities used to teardown databases and users that were created for testing.

  :copyright: (c) 2010 by The Fireworks Project.
  :license: MIT, see LICENSE for more details.
"""

import simplejson
import test_utils

USERNAME = 'test_created_user'
PASSKEY = 'key'
DATABASE = 'test_DB'
DATABASE_TOO = 'test_DB_too'

def teardown():
  """Teardown databases and users that were created for testing
  """
  # Authenticate the test user.
  response = test_utils.make_http_request(
      method='POST',
      url='/users/%s'% USERNAME,
      body=('{"head":{"method":"delete","authorization":["%s"]}}'%
        USERNAME),
      headers={
        'User-Agent': 'UA:DCube teardown :: authenticating testuser',
        'Accept': 'application/jsonrequest',
        'Content-Type': 'application/jsonrequest'})
  assert response.status == 200, (
      'HTTP status is %d when authenticating the temporary test user on '
      '/users/%s'% (response.status, USERNAME))
  json = simplejson.loads(response.body)
  assert json['head']['status'] == 401 or json['head']['status'] == 404, \
      ('DCube status is %d when authenticating the temporary test user on '
      '/users/%s'% (json['head']['status'], USERNAME))

  if json['head']['status'] == 404:
    return

  nonce = json['head']['authorization'][1]
  nextnonce = json['head']['authorization'][2]

  username, cnonce, response = test_utils.create_credentials(
      PASSKEY, USERNAME, nonce, nextnonce)

  # The test user removes himself.
  response = test_utils.make_http_request(
      method='POST',
      url='/users/%s'% USERNAME,
      body='{"head":{"method":"delete", "authorization":["%s","%s","%s"]}}'% \
          (username, cnonce, response),
      headers={
        'User-Agent': 'UA:DCube teardown :: delete testuser',
        'Accept': 'application/jsonrequest',
        'Content-Type': 'application/jsonrequest'})
  assert response.status == 200
  json = simplejson.loads(response.body)
  assert json['head']['status'] == 204

  # Authenticate the admin user.
  response = test_utils.make_http_request(
      method='POST',
      url='/databases/%s'% DATABASE,
      body=('{"head":{"method":"delete","authorization":["%s"]}}'%
        test_utils.ADMIN_USERNAME),
      headers={
        'User-Agent': 'UA:DCube teardown :: authenticating admin user',
        'Accept': 'application/jsonrequest',
        'Content-Type': 'application/jsonrequest'})
  assert response.status == 200, (
      'HTTP status is %d when authenticating the temporary test user on '
      '/databases/%s'% (response.status, DATABASE))
  json = simplejson.loads(response.body)
  assert json['head']['status'] == 401 or json['head']['status'] == 404, \
      'status is %d'% json['head']['status']

  if json['head']['status'] == 404:
    return

  nonce = json['head']['authorization'][1]
  nextnonce = json['head']['authorization'][2]

  username, cnonce, response = test_utils.create_credentials(
      test_utils.ADMIN_PASSKEY, test_utils.ADMIN_USERNAME,
      nonce, nextnonce)

  # Remove the primary test db.
  response = test_utils.make_http_request(
      method='POST',
      url='/databases/%s'% DATABASE,
      body='{"head":{"method":"delete", "authorization":["%s","%s","%s"]}}'% \
          (username, cnonce, response),
      headers={
        'User-Agent': 'UA:DCube teardown :: remove test db.',
        'Accept': 'application/jsonrequest',
        'Content-Type': 'application/jsonrequest'})
  assert response.status == 200
  json = simplejson.loads(response.body)
  assert json['head']['status'] == 204

  # Re-authenticate.
  nonce = json['head']['authorization'][1]
  nextnonce = json['head']['authorization'][2]

  username, cnonce, response = test_utils.create_credentials(
      test_utils.ADMIN_PASSKEY, test_utils.ADMIN_USERNAME,
      nonce, nextnonce)

  # Remove the secondary test db.
  response = test_utils.make_http_request(
      method='POST',
      url='/databases/%s'% DATABASE_TOO,
      body='{"head":{"method":"delete", "authorization":["%s","%s","%s"]}}'% \
          (username, cnonce, response),
      headers={
        'User-Agent': 'UA:DCube teardown :: remove secondary test db.',
        'Accept': 'application/jsonrequest',
        'Content-Type': 'application/jsonrequest'})
  assert response.status == 200
  json = simplejson.loads(response.body)
  assert json['head']['status'] == 204

