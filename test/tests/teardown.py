import simplejson
import test_utils

USERNAME = 'test_created_user'
PASSKEY = 'key'

def teardown():
  response = test_utils.make_http_request(
      method='POST',
      url='/users/%s'% USERNAME,
      body=('{"head":{"method":"delete","authorization":["%s"]}}'%
        USERNAME),
      headers={
        'User-Agent': 'UA:DCube test :: authenticating',
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

  response = test_utils.make_http_request(
      method='POST',
      url='/users/%s'% USERNAME,
      body='{"head":{"method":"delete", "authorization":["%s","%s","%s"]}}'% \
          (username, cnonce, response),
      headers={
        'User-Agent': 'UA:DCube test :: Get all user data.',
        'Accept': 'application/jsonrequest',
        'Content-Type': 'application/jsonrequest'})
  assert response.status == 200
  json = simplejson.loads(response.body)
  assert json['head']['status'] == 204
