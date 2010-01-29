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

  This class of tests works on the default "Not Found" response and the 
  robots.txt response.
  
  It also contains tests that work on the root "/" URL to demonstrate the
  JSONRequest protocol and DCube message format as well as exercise the
  advanced CHAP authentication scheme.

  """

  def test_not_found(self):
    """### Default response for a URL that does not exist. ###

    If an HTTP request is sent to a URL that does not exist on the DCube host a
    response will still be sent back. The response can be expected to follow
    the specified format for "not found" URLs.

    * The response HTTP status will be 404

    * The response HTTP message will be "Not Found"

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

      * A call to "/" requires CHAP authentication, which makes it the ideal
        place to simply authenticate a user.

      * "/" only implements the "get" DCube method.

      * When a DCube "get" call is made to "/" it simply authenticates the
        user, and if the user authenticates, it responds with the host
        information.

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

    The DCube protocol uses a robust challenge-response authentication scheme
    that we call CHAP. It is similar to HTTP digest authentication, but does
    not require the sever to store a plain text password or a long term hashed
    equivalent, but single session hashed password equivalents instead.

    Our scheme is based on the description given by Paul Johnston on his
    [website](http://pajhome.org.uk/crypt/md5/advancedauth.html#alternative).
    On every request, the password equivalent stored on our servers is updated,
    and never repeated.

    This is a good security measure, but it is not easy to grasp on the first
    try.

    These tests demonstrate and excercise CHAP on the root "/" URL.

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
    # credentials without the cnonce and response.
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

    # If the user exists, the server sends back nonce and nextnonce strings in
    # the respose for use to use in calculating the next cnonce and response
    # strings.  The nonce and nextnonce are sha1 hashes that we must use to
    # calculate the conce and response sha1 hashes to authenticate the next
    # call made by this user.
    self.assertEqual(len(json['head']['authorization'][1]), 40)
    self.assertEqual(len(json['head']['authorization'][2]), 40)
    nonce = json['head']['authorization'][1]
    nextnonce = json['head']['authorization'][2]

    username, cnonce, response = test_utils.create_credentials(
        PASSKEY, ADMIN_USERNAME, nonce, nextnonce)

    # After computing a cnonce and response we can add them to the DCube
    # authorization header in the next request to authenticate this user.
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

    # Capture the nonce and nextnonce to authenticate the next request.
    nonce = json['head']['authorization'][1]
    nextnonce = json['head']['authorization'][2]
    self.assertEqual(len(nonce), 40)
    self.assertEqual(len(nextnonce), 40)

    # If we send back a response with invalid cnonce and response, we will be
    # denied access.
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

    # The nonce and nextnonce hashes have not changed since the last call
    # because we did not authenticate.
    self.assertEqual(json['head']['authorization'][1], nonce)
    self.assertEqual(json['head']['authorization'][2], nextnonce)

  def test_robots(self):
    """### Test robots.txt request. ###

    DCube also implements a simple robots.txt file for the web crawling bots
    that care to listen.

    """
    # Only the HTTP 'GET' method is handled by /robots.txt.
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
        headers={'User-Agent':'UA:DCube tests :: POST robots.text'})

    self.assertEqual(response.status, 405)
    self.assertEqual(response.headers['allow'], 'GET')

class UserManagement(unittest.TestCase):
  """## Examine the user management functionality of this DCube host. ##

  This class of tests demonstrates how user management is done on DCube.  All
  user management is done on the "/users/" URL. 

  These tests will get user data, create a new user, and update existing users.
  """
  # The temporary user that we will create for testing. The teardown module is
  # called by the testrunner and will remove this user after the tests have
  # completed.
  username = teardown.USERNAME
  passkey = teardown.PASSKEY

  def test_users_url(self):
    """### The particularities of the "/users/" URL ###

    Every user has a unique URI that can be resolved to a full URL. For
    example, "/users/foo_user" implements all the user management for the user
    "foo_user" and may resolve to
    "http://fireworks-skylight.appspot.com/users/foo_user".
      
      * Like most URLs in this protocol, "/users/" only implements the HTTP "POST"
      method.

      * Also, like most urls in this protocol, "/users/" adheres to the
      [JSONRequest](http://www.json.org/JSONRequest.html) protocol.

      * The base "/users/" URL is not implemented and will return a DCube 501
        response if it is called.

      * If a user does not exist, a call to the user's URI (ie: "/users/foo_user")
        will return a DCube 404 response. This is the ideal method to determine
        if a user exists before trying to create it.

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
          'User-Agent': 'UA:DCube test :: /users/ not implemented',
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
        url='/users/'+ self.username, # The test user should not exist yet.
        body='{"head":{"method":"get"}}',
        headers={
          'User-Agent': 'UA:DCube test :: user not found',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json, {
      'head': {'status': 404,
        'message': 'User "%s" could not be found.'% self.username}})

  def test_check_user(self):
    """### Explore different ways to get user data. ###

    The following HTTP calls to "http://fireworks-skylight.appspot.com/users/"
    url of the DCube api demonstrate the the various ways to get user data.

      * A call to any "/users/" URL using the DCube "get" method does not
        require CHAP authentication, but the information available to
        unauthenticated requests is limited to the username only.

      * An authenticated DCube "get" method call to any "/users/" URL made by
        the user whom the URL represents will return all of the user data in
        the response.

    """

    # A client can discover if a user exists by sending a DCube get message to
    # the user URL. This does not require authentication.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/%s'% ADMIN_USERNAME,
        body='{"head":{"method":"get"}}',
        headers={
          'User-Agent': 'UA:DCube test :: confirm existing user',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json, {
      'body': {'username': ADMIN_USERNAME},
      'head': {'status': 200,
        'message': 'OK'}})

    # Authenticate a user on the "/users/" URL.
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
    # and nextnonce sent from the host, we can finish authenticating this user
    # and get all of the user data.
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
    user = json['body']
    self.assertEqual(user['username'], ADMIN_USERNAME)
    assert isinstance(user['groups'], list)

  def test_create_user(self):
    """### Create a new user. ###

    A new user can be created by making a DCube "put" request to a "/users/" URL
    that does not yet exist.

    * The DCube response from "put"ing a new user includes a nonce and
      nextnonce for authenticating the user on the next request.

    * A newly created user is a member of the "users" group by default.

    * A DCube "put" request to the URL of an existing user will return a DCube
      401 "Authenticate." response.
    
    """

    # A new user can be easily creating by posting the user body to a user URL
    # using the DCube "post" method without authentication.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/%s'% self.username,
        body='{"head":{"method":"put"}}',
        headers={
          'User-Agent': 'UA:DCube test :: Create new user.',
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
          'User-Agent': 'UA:DCube test :: Get new auth user data.',
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
          'User-Agent': 'UA:DCube test :: Unauthenticated user update.',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 401) # 401 Unauthenticated.

  # This test must come after test_create_user().
  def test_user_access(self):
    """### User data access privileges. ###
    
      * Any user who is not a member of the privileged "user_admin" group
        cannot get another users data except for the user name.

      * An authenticated user is able to update any of their own data so long
        as they are a member of a group with the permissions needed to make the
        requested updates.

      * An invalid update, because of group permissions or invalid data, will
        silently fail.  A DCube 200 status response will be sent, but the
        changes will not be made.

    """

    # Authenticate the new user.
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body='{"head":{"method":"get", "authorization":["%s"]}}'% \
            self.username,
        headers={
          'User-Agent': 'UA:DCube test :: Auth new user',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 401)

    self.nonce = json['head']['authorization'][1]
    self.nextnonce = json['head']['authorization'][2]
    username, cnonce, response = test_utils.create_credentials(
        self.passkey, self.username, self.nonce, self.nextnonce)

    # A user who is not a member of the "user_admin" group cannot get access to
    # another users data besides the username.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/'+ ADMIN_USERNAME,
        body='{"head":{"method":"get", "authorization":["%s","%s","%s"]}}'% \
            (username, cnonce, response),
        headers={
          'User-Agent': 'UA:DCube test :: not user_admin',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 200) # Authenticated.
    self.assertEqual(json['body'], {'username': ADMIN_USERNAME})

    self.nonce = json['head']['authorization'][1]
    self.nextnonce = json['head']['authorization'][2]

    # Add admin user to 'user_admin' group.  A user can modify their own data
    # if they are a member of group with the permissions needed to make the
    # changes.  So, in other words, a user that is not a member of a higher
    # level group cannot join higher level groups.
    #
    # Authenticate the test admin user.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/'+ ADMIN_USERNAME,
        body='{"head":{"method":"get", "authorization":["%s"]}}'% \
            ADMIN_USERNAME,
        headers={
          'User-Agent': 'UA:DCube test :: Authenticate.',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 200)

    nonce = json['head']['authorization'][1]
    nextnonce = json['head']['authorization'][2]
    username, cnonce, response = test_utils.create_credentials(
        PASSKEY, ADMIN_USERNAME, nonce, nextnonce)

    # Get the test admin users data.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/'+ ADMIN_USERNAME,
        body='{"head":{"method":"get", "authorization":["%s","%s","%s"]}}'% \
            (ADMIN_USERNAME, cnonce, response),
        headers={
          'User-Agent': 'UA:DCube test :: Auth get user.',
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

    # Add the test admin user to the 'user_admin' group if it is not already.
    if not 'user_admin' in user['groups']:
      user['groups'].append('user_admin')

    # Update the test admin user by making a DCube "post" request.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/'+ ADMIN_USERNAME,
        body=simplejson.dumps({'head':{'method':'put','authorization':creds},'body':user}),
        headers={
          'User-Agent': 'UA:DCube test :: Update user.',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 200)
    user = json['body']
    assert isinstance(user['groups'], list)
    # The test admin user updated their own data.
    assert 'user_admin' in user['groups'], 'groups: %s'% repr(user['groups'])

    nonce = json['head']['authorization'][1]
    nextnonce = json['head']['authorization'][2]
    username, cnonce, response = test_utils.create_credentials(
        PASSKEY, ADMIN_USERNAME, nonce, nextnonce)

    # A user may not delete another user, even a member of the sys_admin group.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/'+ self.username,
        body='{"head":{"method":"delete","authorization":["%s","%s","%s"]}}'% \
            (ADMIN_USERNAME, cnonce, response),
        headers={
          'User-Agent': 'UA:DCube test :: Update user.',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 403)

    # An un-privileged user has limited ability to update even their own user
    # data.
    #
    # Get the credentials for the un-privleged test user.
    creds = test_utils.create_credentials(
        self.passkey, self.username, self.nonce, self.nextnonce)

    # Udate the user data,  adding the "user_admin" group.
    user = {'username': self.username, 'groups': ['users', 'user_admin']}
    response = test_utils.make_http_request(
        method='POST',
        url='/users/'+ self.username,
        body=simplejson.dumps({'head':{'method':'put','authorization':creds},'body':user}),
        headers={
          'User-Agent': 'UA:DCube test :: no user update priv',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 200) # Silently fails.
    user = json['body']
    # The "user_admin" group was not added because this user does not have
    # permission on a level higher than "user_admin".
    self.assertEqual(user['groups'], ['users'])

    # Updating a user with invalid data silently fails.
    #
    # Update the CHAP creds.
    nonce = json['head']['authorization'][1]
    nextnonce = json['head']['authorization'][2]
    creds = test_utils.create_credentials(
        self.passkey, self.username, nonce, nextnonce)

    # Try to add the user to an "invalid_group".
    user = {'username': self.username, 'groups': ['users', 'invalid_group']}
    response = test_utils.make_http_request(
        method='POST',
        url='/users/'+ self.username,
        body=simplejson.dumps(
          {'head':{'method':'put','authorization':creds},'body':user}),
        headers={
          'User-Agent': 'UA:DCube test :: invalid user update',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 200) # Silently fails.
    user = json['body']
    # The "user_admin" group was not added because the "invalid_group" does not
    # exist.
    self.assertEqual(user['groups'], ['users'])

class DatabaseManagement(unittest.TestCase):
  """ ## Database Management ##

  This class defines a set of tests that demonstrate the database management
  functionality of a DCube host.

  All HTTP requests made to manage any database are made to the  "/databases/"
  URL.  These tests will create, get, and update database metadata.

  """

  # The temporary user that has been created for testing. The teardown module
  # is called by the testrunner and will remove this user after the tests have
  # completed.
  username = teardown.USERNAME
  passkey = teardown.PASSKEY
  database = teardown.DATABASE

  def test_databases_url(self):
    """### The particularities of the "/databases/" URL ###

    Every database has a unique URI that can be resolved to a full URL. For
    example, "/databases/foo_database" implements all the database management
    functionality for the database "foo_database" and may resolve to
    "http://fireworks-skylight.appspot.com/databases/foo_user".
      
      * Like most URLs in this protocol, "/databases/" only implements the HTTP "POST"
      method.

      * Also, like most urls in this protocol, "/databases/" adheres to the
      [JSONRequest](http://www.json.org/JSONRequest.html) protocol.

      * The base "/databases/" URL is not implemented and will return a DCube 501
        response if it is called.

      * If a database does not exist, a request to the database URI (ie:
        "/databases/foo_database") will return a DCube 404 response. This is
        the ideal method to determine if a database exists before trying to
        create it.
    """

    # HTTP GET method is not allowed in DCube protocol.
    response = test_utils.make_http_request(
        method='GET',
        url='/databases/'+ self.database,
        body=None,
        headers={'User-Agent': 'UA:DCube test :: GET method not allowed'})
    self.assertEqual(response.status, 405)
    self.assertEqual(response.message, 'Method Not Allowed')
    # The "Allow" header indicates HTTP methods that are allowed.
    self.assertEqual(response.headers['allow'], 'POST')

    # HTTP PUT method is not allowed in DCube protocol.
    response = test_utils.make_http_request(
        method='PUT',
        url='/databases/'+ self.database,
        body=None,
        headers={'User-Agent': 'UA:DCube test :: PUT method not allowed'})
    self.assertEqual(response.status, 405)
    self.assertEqual(response.message, 'Method Not Allowed')
    # The "Allow" header indicates HTTP methods that are allowed.
    self.assertEqual(response.headers['allow'], 'POST')

    # Accessing '/databases/' without a database URL results in a DCube 501 "Not
    # implemented." status.
    response = test_utils.make_http_request(
        method='POST',
        url='/databases/',
        body='{"head":{"method":"get"}}',
        headers={
          'User-Agent': 'UA:DCube test :: /databases/ not implemented',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json, {
      'head': {'status': 501,
        'message': 'The URL "/databases/" is not implemented on this host.'}})

    # Accessing a url for a database that does not exist results in a DCube 404
    # "Not found." status.
    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database, # The test db should not exist yet.
        body='{"head":{"method":"get"}}',
        headers={
          'User-Agent': 'UA:DCube test :: user not found',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json, {
      'head': {'status': 404,
        'message': 'Database "%s" could not be found.'% self.database}})

  def test_create_database(self):
    """### Create a new database. ###

    In this test we actually test access methods and permissions of a new
    database after creating it.

      * A user must authenticate and must be a member of the "database"
        permission group level to create a new database.

      * Any unauthenticated user can make a DCube "get" request to a database
        URL, but the information returned will be limited to the database name
        only.

      * An authenticated user who is also in the "owner access list" or
        "manager access list" of the database will get all of the database info
        returned in a response to a DCube "get" request.

      * Only an authenticated user that is a member of the sys_admin permission
        level group can delete a datbase.

    """

    # An unauthenticated user cannot create a database.
    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database, # The test db should not exist yet.
        body='{"head":{"method":"put"}}',
        headers={
          'User-Agent': 'UA:DCube test :: Unauthenticated database put',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 401)
    self.assertEqual(json['head']['message'], 'No authorization credentials.')

    # Authenticate the test user.
    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database, # The test db should not exist yet.
        body='{"head":{"method":"put", "authorization":["%s"]}}'% \
            self.username,
        headers={
          'User-Agent': 'UA:DCube test :: Auth test user',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 401)

    self.nonce = json['head']['authorization'][1]
    self.nextnonce = json['head']['authorization'][2]
    username, cnonce, response = test_utils.create_credentials(
        self.passkey, self.username, self.nonce, self.nextnonce)

    # A user who is not a member of the "database" group cannot create a
    # database.
    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database, # The test db should not exist yet.
        body='{"head":{"method":"put", "authorization":["%s","%s","%s"]}}'% \
            (username, cnonce, response),
        headers={
          'User-Agent': 'UA:DCube test :: no permission to create db',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    # Authenticated but forbidden.
    self.assertEqual(json['head']['status'], 403)

    self.nonce = json['head']['authorization'][1]
    self.nextnonce = json['head']['authorization'][2]

    # Authenticate the test admin user.
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
    username, cnonce, response = test_utils.create_credentials(
        PASSKEY, ADMIN_USERNAME,
        json['head']['authorization'][1],
        json['head']['authorization'][2])

    # The test admin user should be a member of the "database" group and may
    # create a database.
    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database, # The test db should not exist yet.
        body='{"head":{"method":"put", "authorization":["%s","%s","%s"]}}'% \
            (username, cnonce, response),
        headers={
          'User-Agent': 'UA:DCube test :: create new db',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 201)
    db = json['body']
    self.assertEqual(db['name'], self.database)
    self.assertEqual(db['owner_acl'], [ADMIN_USERNAME])

    username, cnonce, response = test_utils.create_credentials(
        PASSKEY, ADMIN_USERNAME,
        json['head']['authorization'][1],
        json['head']['authorization'][2])

    # Get the database we just created.  An authenticated user that is a
    # manager or owner can get all of the database info.
    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database,
        body='{"head":{"method":"get", "authorization":["%s","%s","%s"]}}'% \
            (username, cnonce, response),
        headers={
          'User-Agent': 'UA:DCube test :: get db authenticated',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 200)
    db = json['body']
    self.assertEqual(db,
         {'name': self.database,
          'owner_acl': [ADMIN_USERNAME],
          'manager_acl': None,
          'user_acl': None})

    # An unauthenticated user can get the database name.
    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database,
        body='{"head":{"method":"get"}}',
        headers={
          'User-Agent': 'UA:DCube test :: get db unauthenticated',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json, {
      'head': {'status': 200, 'message': 'OK'},
      'body': {'name': self.database}})

    # An authenticated user that is not a manager can get the database name.
    username, cnonce, response = test_utils.create_credentials(
        self.passkey, self.username,
        self.nonce,
        self.nextnonce)

    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database,
        body='{"head":{"method":"get", "authorization":["%s","%s","%s"]}}'% \
            (username, cnonce, response),
        headers={
          'User-Agent': 'UA:DCube test :: non owner get db',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 200)
    db = json['body']
    self.assertEqual(db, {'name': self.database})

    self.nonce = json['head']['authorization'][1]
    self.nextnonce = json['head']['authorization'][2]
    username, cnonce, response = test_utils.create_credentials(
        self.passkey, self.username, self.nonce, self.nextnonce)

    # Only a sys_admin user can remove a db.
    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database,
        body='{"head":{"method":"delete", "authorization":["%s","%s","%s"]}}'% \
            (username, cnonce, response),
        headers={
          'User-Agent': 'UA:DCube test :: non owner get db',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 403)

  def test_database_update(self):
    """### Update a database. ###
    """

    # An unauthenticated user cannot update a database.
    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database, # The test db should not exist yet.
        body='{"head":{"method":"put"}}',
        headers={
          'User-Agent': 'UA:DCube test :: Unauthenticated database put',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 401)
    self.assertEqual(json['head']['message'], 'No authorization credentials.')

    # Authenticate the test user.
    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database, # The test db should not exist yet.
        body='{"head":{"method":"put", "authorization":["%s"]}}'% \
            self.username,
        headers={
          'User-Agent': 'UA:DCube test :: Auth test user',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 401)

    self.nonce = json['head']['authorization'][1]
    self.nextnonce = json['head']['authorization'][2]
    creds = test_utils.create_credentials(
        self.passkey, self.username, self.nonce, self.nextnonce)

    # A user who is not a member of the owner access list for this database
    # cannot update manager access list.
    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database,
        body=simplejson.dumps({'head':{'method':'put','authorization':creds},
          'body':{'name':self.database, 'manager_acl':[self.username]}}),
        headers={
          'User-Agent': 'UA:DCube test :: no permission to update db',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    # Authenticated but the operation was forbidden.
    self.assertEqual(json['head']['status'], 403)

    self.nonce = json['head']['authorization'][1]
    self.nextnonce = json['head']['authorization'][2]
    creds = test_utils.create_credentials(
        self.passkey, self.username, self.nonce, self.nextnonce)

    # A user who is not a member of the manager ACL or owner ACL for this
    # database cannot update user ACL.
    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database,
        body=simplejson.dumps({'head':{'method':'put','authorization':creds},
          'body':{'name':self.database, 'user_acl':['foo_user']}}),
        headers={
          'User-Agent': 'UA:DCube test :: no permission to update db',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    # Authenticated but the operation was forbidden.
    self.assertEqual(json['head']['status'], 403)

    self.nonce = json['head']['authorization'][1]
    self.nextnonce = json['head']['authorization'][2]

    # Authenticate the test admin user
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
    creds = test_utils.create_credentials(
        PASSKEY, ADMIN_USERNAME,
        json['head']['authorization'][1],
        json['head']['authorization'][2])

    # An authenticated user who is a member of the owner access list can add a
    # user to the manager access list.
    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database,
        body=simplejson.dumps({'head':{'method':'put','authorization':creds},
          'body':{'name':self.database, 'manager_acl':[self.username]}}),
        headers={
          'User-Agent': 'UA:DCube test :: no permission to create db',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    db = json['body']
    self.assertEqual(db['manager_acl'], [self.username])
    self.admin_creds = test_utils.create_credentials(
        PASSKEY, ADMIN_USERNAME,
        json['head']['authorization'][1],
        json['head']['authorization'][2])

    # An authenticated user who is not on the owner ACL for a database cannot
    # add users to the manager access list.
    db['manager_acl'].append('foo_user')

    creds = test_utils.create_credentials(
        self.passkey, self.username, self.nonce, self.nextnonce)

    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database,
        body=simplejson.dumps({
          'head':{'method':'put','authorization':creds},
          'body':db}),
        headers={
          'User-Agent': 'UA:DCube test :: no permission to update db',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    # Authenticated, but forbidden to update.
    self.assertEqual(json['head']['status'], 403)

    self.nonce = json['head']['authorization'][1]
    self.nextnonce = json['head']['authorization'][2]

    # An authenticated user that is on the manager ACL can add users to the
    # users ACL.
    creds = test_utils.create_credentials(
        self.passkey, self.username, self.nonce, self.nextnonce)

    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database,
        body=simplejson.dumps({'head':{'method':'put','authorization':creds},
          'body':{'name':self.database, 'user_acl':['foo_user']}}),
        headers={
          'User-Agent': 'UA:DCube test :: no permission to update db',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    # Authenticated but the operation was forbidden.
    self.assertEqual(json['head']['status'], 200)
    self.assertEqual(json['body']['user_acl'], ['foo_user'])

    self.nonce = json['head']['authorization'][1]
    self.nextnonce = json['head']['authorization'][2]

    # A user who is a member of the "account_admin" permission level group can
    # add a user to the owner access list of a database.
    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database,
        body=simplejson.dumps({'head':{'method':'put','authorization':self.admin_creds},
          'body':{'owner_acl':[ADMIN_USERNAME, self.username]}}),
        headers={
          'User-Agent': 'UA:DCube test :: no permission to create db',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 200)
    db = json['body']
    self.assertEqual(db['owner_acl'], [ADMIN_USERNAME, self.username])

    self.admin_creds = test_utils.create_credentials(
        PASSKEY, ADMIN_USERNAME,
        json['head']['authorization'][1],
        json['head']['authorization'][2])

    # An authenticated user who is not an admin, but is on the owner ACL for a
    # database can add a user to the manager ACL.
    db['manager_acl'].append('foo_user')

    creds = test_utils.create_credentials(
        self.passkey, self.username, self.nonce, self.nextnonce)

    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database,
        body=simplejson.dumps({
          'head':{'method':'put','authorization':creds},
          'body':db}),
        headers={
          'User-Agent': 'UA:DCube test :: no permission to update db',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['head']['status'], 200)
    # Updated the manager ACL
    db = json['body']
    self.assertEqual(db['manager_acl'], [self.username, 'foo_user'])

    self.nonce = json['head']['authorization'][1]
    self.nextnonce = json['head']['authorization'][2]

    # But, a user who is not a an admin cannot add users to the owner ACL of a
    # database.
    db['owner_acl'].append('foo_user')

    creds = test_utils.create_credentials(
        self.passkey, self.username, self.nonce, self.nextnonce)

    response = test_utils.make_http_request(
        method='POST',
        url='/databases/'+ self.database,
        body=simplejson.dumps({
          'head':{'method':'put','authorization':creds},
          'body':db}),
        headers={
          'User-Agent': 'UA:DCube test :: no permission to update db',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    # Forbidden
    self.assertEqual(json['head']['status'], 403)

