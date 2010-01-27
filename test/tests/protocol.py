import unittest

import simplejson
import test_utils
import teardown

HOST = test_utils.HOST
LOCAL = test_utils.LOCAL
ADMIN_USERNAME = test_utils.ADMIN_USERNAME
PASSKEY = test_utils.ADMIN_PASSKEY

class Basic(unittest.TestCase):
  """## Define tests to examine basic functionality of this DCube host. ##
  
  These tests dive into the default "Not Found" response, the hosted doc pages,
  the JSONRequest protocol and the DCube message format on the root URL, CHAP
  authentication, and the robots.txt file.

  """

  def test_not_found(self):
    """### Requesting a URL that does not exist. ###

    If an HTTP request is sent to a URL that does not exist on the DCube host
    the response will still be sent back. It can be expected to follow the specified
    format for "not found" URLs.

    * The response status will be 404

    * The response message will be "Not Found"

    * There will be no message body.

    """
    response = test_utils.make_http_request(
        method='GET',
        url='/lost_city_of_atlantis',
        body=None,
        headers={'User-Agent':'UA:DCube test :: not found',
                 'Host': HOST})

    self.assertEqual(response.status, 404)

    self.assertEqual(response.message, 'Not Found') 
    self.assertEqual(response.headers['cache-control'],
                     'public')
    # We can't check the expires header directly because of time skew.
    self.assertEqual(len(response.headers['expires']), 29)
    self.assertEqual(response.body, '') 

  def test_root(self):
    """### Basic HTTP calls to the root "/" url. ###

    The following HTTP calls to the root
    "http://fireworks-skylight.appspot.com/" url of the DCube api demonstrate
    the trivial utility it provides.
      
      * Like most urls in this protocol, "/" only implements the HTTP "POST"
      method.

      * Also, like most urls in this protocol, "/" adheres to the
      [JSONRequest](http://www.json.org/JSONRequest.html) protocol.

      * A call to "/" requires CHAP authentication.

      * "/" only implements the "get" DCube method.

      * When a DCube "get" call is made to "/" it simply
      authenticates the user, and if the user authenticates,
      it responds with the host information.

    """
    # Only allows POST requests.
    response = test_utils.make_http_request(
        method='GET',
        url='/',
        body=None,
        headers={'User-Agent': 'UA:DCube test :: method not allowed'})
    self.assertEqual(response.status, 405)
    self.assertEqual(response.message, 'Method Not Allowed')
    # The "Allow" header informs us of the only HTTP method we can use on this URL.
    self.assertEqual(response.headers['allow'], 'POST')
    self.assertEqual(response.body, '')

    # The Content-Type header on the request must be application/jsonrequest.
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body='{}', # There must be a body in a POST request.
        headers={
          'User-Agent': 'UA:DCube test :: invalid Content-Type',
          'Content-Length': 2,
          'Content-Type': 'application/x-www-form-urlencoded'})
    self.assertEqual(response.status, 415)
    self.assertEqual(response.message, 'Unsupported Media Type')

    # The body of the request must be valid JSON.
    body = 'invalid json'
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body=body,
        headers={
          'User-Agent': 'UA:DCube test :: invalid JSON',
          'Accept': 'application/jsonrequest',
          'Content-Length': len(body),
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 400)
    self.assertEqual(response.message, 'Bad Request')
    self.assertEqual(response.headers['content-type'], 'text/plain')
    self.assertEqual(response.body, ('Invalid JSON text body : (invalid json)'))

    # The body of the request must be a JSON encoded {} object.
    body = '[1,2,3]'
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body=body, # Valid JSON, but it's not an {} object.
        headers={
          'User-Agent': 'UA:DCube test :: body not a dict',
          'Accept': 'application/jsonrequest',
          'Content-Length': len(body),
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 400)
    self.assertEqual(response.message, 'Bad Request')
    self.assertEqual(response.headers['content-type'], 'text/plain')
    self.assertEqual(response.body, ('Invalid JSON text body : ([1,2,3])'))

    # The JSONRequest body must contain a 'head' attribute that is a dictionary.
    body = '{}'
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body=body, # Valid JSON, but no 'head'.
        headers={
          'User-Agent': 'UA:DCube test :: no head',
          'Accept': 'application/jsonrequest',
          'Content-Length': len(body),
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 400)
    self.assertEqual(response.message, 'Bad Request')
    self.assertEqual(response.headers['content-type'], 'text/plain')
    self.assertEqual(response.body, 'Missing DCube message "head" in ({})')

    # The JSONRequest 'head' attribute must contain a 'method' attribute that
    # is is the name of the function to invoke on this url.
    body = '{"head":{}}'
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body=body, # Valid JSON, but no 'method'.
        headers={
          'User-Agent': 'UA:DCube test :: no method',
          'Accept': 'application/jsonrequest',
          'Content-Length': len(body),
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 400)
    self.assertEqual(response.message, 'Bad Request')
    self.assertEqual(response.body, 'Missing DCube message header "method" in ({"head":{}})')

    # The root '/' url only accepts the 'get' DCube method
    body = '{"head":{"method":"post"}}'
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body=body,
        headers={
          'User-Agent': 'UA:DCube test :: invalid method',
          'Accept': 'application/jsonrequest',
          'Content-Length': len(body),
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json, {
      'head': {'status': 405,
        'message': 'Invalid method "post".'}})

  def test_authenticate(self):
    """### Authenticating a user on the root '/' URL ###

    The DCube protocol uses a robust and challenge response authentication
    scheme that we call CHAP. It is similar to HTTP digest authentication, but
    does not require the sever to store a plain text password, but hashed
    password equivalents instead.

    Our scheme is based on the description given by Paul Johnston on his
    [website](http://pajhome.org.uk/crypt/md5/advancedauth.html#alternative).
    On every request, the password equivalent stored on our servers is updated,
    and never repeated.

    This is a good security measure, but it is not easy to grasp on the first
    try. So, take a look and then come back to it again later.

    """
    # We can't authenticate without the authorization part of the head.
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body='{"head":{"method":"get"}}',
        headers={
          'User-Agent': 'UA:DCube test :: no authorization',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json, {
      'head': {'status': 401,
        'message': 'No authorization credentials.'}})

    # And the user name must be a string.
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body='{"head":{"method":"get", "authorization":[null,"x","y"]}}',
        headers={
          'User-Agent': 'UA:DCube test :: null username',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json, {
      'head': {'status': 401,
        'message': 'Username "null" is invalid.',}})

    # If the user does not exist, the server does not send back authentication
    # info.
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body=('{"head":{"method":"get",'
              '"authorization":["not_really_aUser","x","y"]}}'),
        headers={
          'User-Agent': 'UA:DCube test :: user na',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json, {
      'head': {'status': 401,
        'message': 'Username "not_really_aUser" does not exist.'}})

    # We start a new authenticated session by just sending the username in the
    # credentials.
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body='{"head":{"method":"get", "authorization":["%s"]}}'% \
            ADMIN_USERNAME,
        headers={
          'User-Agent': 'UA:DCube test :: authenticate',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 401) # Unauthenticated.
    self.assertEqual(json['head']['message'], 'Authenticate.')
    self.assertEqual(json['head']['authorization'][0], ADMIN_USERNAME)

    # nonce and nextnonce are sha1 hashes that we must use to calculate the
    # conce and response to authenticate the next call.
    self.assertEqual(len(json['head']['authorization'][1]), 40)
    self.assertEqual(len(json['head']['authorization'][2]), 40)
    nonce = json['head']['authorization'][1]
    nextnonce = json['head']['authorization'][2]

    username, cnonce, response = test_utils.create_credentials(
        PASSKEY, ADMIN_USERNAME, nonce, nextnonce)

    # With a cnonce and response computed from the user's passkey and the nonce
    # and nextnonce sent from the host, we can authenticate this user.
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body='{"head":{"method":"get", "authorization":["%s","%s","%s"]}}'% \
            (ADMIN_USERNAME, cnonce, response),
        headers={
          'User-Agent': 'UA:DCube test :: Authorized',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 200) # Authenticated.
    self.assertEqual(json['head']['message'], 'OK')
    self.assertEqual(json['head']['authorization'][0], ADMIN_USERNAME)
    # We got access.
    self.assertEqual(json['body'], 'DCube host on Google App Engine.')

    # nonce and nextnonce are sha1 hashes that we must use to calculate the
    # conce and response to authenticate the next call.
    nonce = json['head']['authorization'][1]
    nextnonce = json['head']['authorization'][2]
    self.assertEqual(len(nonce), 40)
    self.assertEqual(len(nextnonce), 40)

    # If we send back a response with invalid credentials, we will be denied
    # access.
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body='{"head":{"method":"get", "authorization":["%s","%s","%s"]}}'% \
            (ADMIN_USERNAME, 'foostring', 'barstring'),
        headers={
          'User-Agent': 'UA:DCube test :: Auth denied.',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 401) # Unauthenticated.
    self.assertEqual(json['head']['message'], 'Authenticate.')
    self.assertEqual(json['head']['authorization'][0], ADMIN_USERNAME)
    # Denied access.
    self.assertEqual(json.get('body'), None)

    # nonce and nextnonce are sha1 hashes that we must use to calculate the
    # conce and response to authenticate the next call have not changed since
    # the last call because we did not authenticate.
    self.assertEqual(json['head']['authorization'][1], nonce)
    self.assertEqual(json['head']['authorization'][2], nextnonce)

  def test_robots(self):
    """### Test the robots.txt call. ###

    DCube also implements a simple robots.txt file for the web crawling bots
    that care to listen.

    """
    # todo: We should not allow POST or PUT requests to robots.txt
    response =  test_utils.make_http_request(
        method='GET',
        url='/robots.txt',
        body=None,
        headers={'User-Agent':'UA:DCube tests :: robots.text'})

    self.assertEqual(response.status, 200)
    self.assertEqual(response.headers['content-type'],
                       'text/plain')
    # todo: Why are we not getting a content-length header from the server???
    # self.assertEqual(response.headers['content-length'], '25')
    self.assertEqual(response.headers['cache-control'],
                     'public')
    self.assertEqual(response.headers['last-modified'],
                     'Fri, 1 Jan 2010 00:00:01 GMT')
    # We can't check the expires header directly because of time skew.
    self.assertEqual(len(response.headers['expires']), 29)
    self.assertEqual(response.body, 'User-agent: *\nDisallow: /') 

    response =  test_utils.make_http_request(
        method='POST',
        url='/robots.txt',
        body=None,
        headers={'User-Agent':'UA:DCube tests :: robots.text'})

    self.assertEqual(response.status, 405)
    self.assertEqual(response.headers['allow'], 'GET')

class UserManagement(unittest.TestCase):
  username = teardown.USERNAME
  passkey = teardown.PASSKEY

  def test_users_url(self):
    """### The particularities of the "/users/" URL ###

    """

    # HTTP GET method is not allowed in DCube protocol.
    response = test_utils.make_http_request(
        method='GET',
        url='/users/foo_user',
        body=None,
        headers={'User-Agent': 'UA:DCube test :: GET method not allowed'})
    self.assertEqual(response.status, 405)
    self.assertEqual(response.message, 'Method Not Allowed')
    # The "Allow" header indicates HTTP methods that are allowed.
    self.assertEqual(response.headers['allow'], 'POST')

    # HTTP PUT method is not allowed in DCube protocol.
    response = test_utils.make_http_request(
        method='PUT',
        url='/users/foo_user',
        body=None,
        headers={'User-Agent': 'UA:DCube test :: PUT method not allowed'})
    self.assertEqual(response.status, 405)
    self.assertEqual(response.message, 'Method Not Allowed')
    # The "Allow" header indicates HTTP methods that are allowed.
    self.assertEqual(response.headers['allow'], 'POST')

    # Accessing '/users/' without a username URL results in a DCube 501 "Not
    # implemented." status.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/',
        body='{"head":{"method":"get"}}',
        headers={
          'User-Agent': 'UA:DCube test :: get na user',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json, {
      'head': {'status': 501,
        'message': 'The URL "/users/" is not implemented on this host.'}})

    # Accessing a url for a user that does not exist results in a DCube 404
    # "Not found." status.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/foo_user',
        body='{"head":{"method":"get"}}',
        headers={
          'User-Agent': 'UA:DCube test :: get na user',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json, {
      'head': {'status': 404,
        'message': 'User "foo_user" could not be found.'}})

  def test_check_user(self):
    """### Explore different ways to get user data. ###

    The following HTTP calls to "http://fireworks-skylight.appspot.com/users/"
    url of the DCube api demonstrate the the various ways to get user data.
      
      * A call to "/users/" without making the username part of the URL will
        result in a DCube 501 "Not implemented." So, for example,
        "users/some_username" will work, but "/users/" will not.

      * Like most urls in this protocol, all "/users/" URLs only implement the
        HTTP "POST" method.

      * Also, like most urls on this host, "/users/" URLs adhere to the
        [JSONRequest](http://www.json.org/JSONRequest.html) protocol.

      * A call to any "/users/" URL using the DCube "get" method does not
        require CHAP authentication, but the information available to
        unauthenticated requests is limited to the username only.

      * CHAP Authenticated calls to any "/users/" URL will allow access to
        privileged user data in some cases. In the case of a "get" request
        additional user data will be returned if the authenticated user is a
        member of the "user_admin" group, or the user himself. In the case of a
        "delete" request, if the authenticated user is not the user himself,
        the response is a DCube status "403 Forbidden". In the case of a "put"
        request, if the user already exists, the authenticated user must be a
        member of the "user_admin" group or the user himself to make the
        requested changes.  If so, a 200 response is returned, and if not a 403
        response is returned.

      * If a "put" request is made on a user url that does not exist, the user
        is created without requiring authentication.

    """

    # A client can discover if a user exists by sending a DCube get message to
    # the user URL. This does not require authentication.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/%s'% ADMIN_USERNAME,
        body='{"head":{"method":"get"}}',
        headers={
          'User-Agent': 'UA:DCube test :: get existing user',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json, {
      'body': {'username': ADMIN_USERNAME},
      'head': {'status': 200,
        'message': 'OK'}})

    # A client can get all user data if the user is authenticated.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/%s'% ADMIN_USERNAME,
        body=('{"head":{"method":"get","authorization":["%s"]}}'%
          ADMIN_USERNAME),
        headers={
          'User-Agent': 'UA:DCube test :: authenticating',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['body'], {'username': ADMIN_USERNAME})
    self.assertEqual(json['head']['status'], 200)

    # We need the nonce and nextnonce to authenticate the user on the next
    # request.
    nonce = json['head']['authorization'][1]
    nextnonce = json['head']['authorization'][2]

    username, cnonce, response = test_utils.create_credentials(
        PASSKEY, ADMIN_USERNAME, nonce, nextnonce)

    # With a cnonce and response computed from the user's passkey and the nonce
    # and nextnonce sent from the host, we can finish authenticating this user.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/%s'% ADMIN_USERNAME,
        body='{"head":{"method":"get", "authorization":["%s","%s","%s"]}}'% \
            (ADMIN_USERNAME, cnonce, response),
        headers={
          'User-Agent': 'UA:DCube test :: Get all user data.',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 200)
    self.assertEqual(json['body'], {'username': ADMIN_USERNAME,
      'groups':['users', 'sys_admin']})

  def test_create_user(self):
    """### Create a new user. ###
    
    """

    # A new user can be easily creating by posting the user body to a user URL
    # using the DCube "post" method without authentication.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/%s'% self.username,
        body='{"head":{"method":"put"}}',
        headers={
          'User-Agent': 'UA:DCube test :: Get all user data.',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 201) # 202 status "Created."
    # A new user is created as a member of the 'users' group by default.
    self.assertEqual(json['body'], {'username': self.username})

    # The new user response includes the nonce and nextnonce sha1 hashes that
    # we must use to calculate the conce and response to authenticate the next
    # call.
    nonce = json['head']['authorization'][1]
    nextnonce = json['head']['authorization'][2]
    self.assertEqual(len(nonce), 40)
    self.assertEqual(len(nextnonce), 40)

    username, cnonce, response = test_utils.create_credentials(
        self.passkey, self.username, nonce, nextnonce)

    # The new user can retrieve all of their data with an authenticated DCube
    # "get" request.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/'+ self.username,
        body='{"head":{"method":"get", "authorization":["%s","%s","%s"]}}'% \
            (username, cnonce, response),
        headers={
          'User-Agent': 'UA:DCube test :: Authorized',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 200) # Authenticated.
    self.assertEqual(json['body'], {'username': self.username, 'groups': ['users']})

    # We cannot update an existing user without authenticating.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/%s'% self.username,
        body='{"head":{"method":"put"}}',
        headers={
          'User-Agent': 'UA:DCube test :: Get all user data.',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 401) # 401 Unauthenticated.

  # This test must come after test_create_user().
  def test_user_access(self):
    """### User data access privileges.
    
    """

    # Authenticate the new user.
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body='{"head":{"method":"get", "authorization":["%s"]}}'% \
            self.username,
        headers={
          'User-Agent': 'UA:DCube test :: Authorized',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 401)

    nonce = json['head']['authorization'][1]
    nextnonce = json['head']['authorization'][2]
    username, cnonce, response = test_utils.create_credentials(
        self.passkey, self.username, nonce, nextnonce)

    # A user who is not a member of the 'user_admin' group cannot access user
    # data that does not belong to them.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/'+ ADMIN_USERNAME,
        body='{"head":{"method":"get", "authorization":["%s","%s","%s"]}}'% \
            (username, cnonce, response),
        headers={
          'User-Agent': 'UA:DCube test :: Authorized',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 200) # Authenticated.
    self.assertEqual(json['body'], {'username': ADMIN_USERNAME})

    #nonce = json['head']['authorization'][1]
    #nextnonce = json['head']['authorization'][2]
    #username, cnonce, response = test_utils.create_credentials(
        #self.passkey, self.username, nonce, nextnonce)

    # Add test user to 'user_admin' group.
    # A user can modify their own data if they are a member of a high enough group.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/'+ ADMIN_USERNAME,
        body='{"head":{"method":"get", "authorization":["%s"]}}'% \
            ADMIN_USERNAME,
        headers={
          'User-Agent': 'UA:DCube test :: Authorized',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 200)

    nonce = json['head']['authorization'][1]
    nextnonce = json['head']['authorization'][2]
    username, cnonce, response = test_utils.create_credentials(
        PASSKEY, ADMIN_USERNAME, nonce, nextnonce)

    response = test_utils.make_http_request(
        method='POST',
        url='/users/'+ ADMIN_USERNAME,
        body='{"head":{"method":"get", "authorization":["%s","%s","%s"]}}'% \
            (ADMIN_USERNAME, cnonce, response),
        headers={
          'User-Agent': 'UA:DCube test :: Authorized',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    user = json['body']
    self.assertEqual(json['body']['username'], ADMIN_USERNAME)
    assert isinstance(user['groups'], list)

    nonce = json['head']['authorization'][1]
    nextnonce = json['head']['authorization'][2]
    creds = test_utils.create_credentials(
        PASSKEY, ADMIN_USERNAME, nonce, nextnonce)

    # Add the 'user_admin' group.
    if not 'user_admin' in user['groups']:
      user['groups'].append('user_admin')

    response = test_utils.make_http_request(
        method='POST',
        url='/users/'+ ADMIN_USERNAME,
        body=simplejson.dumps({'head':{'method':'put','authorization':creds},'body':user}),
        headers={
          'User-Agent': 'UA:DCube test :: Authorized',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 200)

