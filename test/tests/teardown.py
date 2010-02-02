import simplejson
import test_utils

USERNAME = 'test_created_user'
PASSKEY = 'key'
DATABASE = 'test_DB'

def teardown():
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
  assert response.status == 200, 'HTTP status is: %d'% response.status
  json = simplejson.loads(response.body)
  assert json['head']['status'] == 401 or json['head']['status'] == 404, \
      'status is %d'% json['head']['status']

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
  assert response.status == 200, 'HTTP status is: %d'% response.status
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

  # Remove the test db.
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
