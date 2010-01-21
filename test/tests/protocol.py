import unittest

import simplejson
import test_utils

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

    * The default content type will be application/jsonrequest unless another
    content type is specified in the "Accept" header of the request. Other than
    application/jsonrequest the only other content types supported are text/html
    and text/plain.

    * The response message will be the string `"The URL "REQUEST_URL" could not
    be found on the CURRENT_HOST host."` The variables REQUEST_URL and
    CURRENT_HOST will be replaced by the URL string requested and the
    current host domain name respectively.

    """
    def trivial_checks(response):
      self.assertEqual(response.message, 'Not Found') 
      self.assertEqual(response.headers['cache-control'],
                       'public')
      self.assertEqual(response.headers['last-modified'],
                       'Fri, 1 Jan 2010 00:00:01 GMT')
      # We can't check the expires header directly because of time skew.
      self.assertEqual(len(response.headers['expires']), 29)


    # The accept header is not specified
    response = test_utils.make_http_request(
        method='GET', # Try a HTTP GET request
        url='/lost_city_of_atlantis',
        body=None,
        headers={'Accept':None,
                 'User-Agent':'UA:DCube test :: not found / no-accept',
                 'Host': HOST})

    expected_response_body = ("The URL '/lost_city_of_atlantis' "
        "could not be found on the %s host."% HOST)

    self.assertEqual(response.status, 404)
    self.assertEqual(response.body, '"%s"'% expected_response_body) 
    self.assertEqual(response.headers['content-type'],
                       'application/jsonrequest')

    trivial_checks(response)

    # text/plain
    response = test_utils.make_http_request(
        method='PUT', # Try a HTTP PUT request
        url='/lost_city_of_atlantis',
        body=None,
        headers={'Accept':'text/plain',
              'User-Agent':'UA:DCube test :: not found / text/plain',
              'Content-Length': '0',
              # Without the Content-Length header the server will respond with
              # a 411 Length Required.
              'Host': HOST})

    expected_response_body = ("The URL '/lost_city_of_atlantis' "
        "could not be found on the %s host."% HOST)

    self.assertEqual(response.status, 404)
    self.assertEqual(response.body, '%s'% expected_response_body) 
    self.assertEqual(response.headers['content-type'],
                       'text/plain')

    trivial_checks(response)

    # text/html
    response = test_utils.make_http_request(
        method='POST', # Try a HTTP POST request
        url='/lost_city_of_atlantis',
        body=None,
        headers={'Accept':'text/html',
              'User-Agent':'UA:DCube test :: not found / text/html',
              'Content-Length': '0',
              # Without the Content-Length header the server will respond with
              # a 411 Length Required.
              'Host': HOST})

    expected_response_body = ("The URL '/lost_city_of_atlantis' "
        "could not be found on the %s host."% HOST)

    self.assertEqual(response.status, 404)
    self.assertEqual(response.body,
        '<h1>Not Found</h1>\n<p>%s</p>'% expected_response_body) 
    self.assertEqual(response.headers['content-type'],
                       'text/html')

    trivial_checks(response)

  def test_docs(self):
    """### Protocol Documentation ###

    The protocol documentation for this DCube host can be found at
    "http://fireworks-skylight.appspot.com/docs/"

    __NOTE!__ The documentation body has not been implemented yet, so a
    simple HTTP 404 status header is returned instead.

    """
    # Make an HTTP 'GET' request on
    # "http://fireworks-skylight.appspot.com/docs/".
    response = test_utils.make_http_request(
        method='GET',
        url='/docs/',
        body=None,
        headers={'User-Agent':'UA:DCube test:: get docs'})

    self.assertEqual(response.status, 404)

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
    self.assertEqual(response.body, 'HTTP method "GET" is invalid for DCube protocol.')

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
    self.assertEqual(response.body,
        'Content-Type "application/x-www-form-urlencoded" is invalid for JSONRequest protocol.')

    # The Accept header on the request must be application/jsonrequest.
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body='a',
        headers={
          'User-Agent': 'UA:DCube test :: invalid Accept',
          'Content-Length': 1,
          'Accept': 'text/html',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 406)
    self.assertEqual(response.message, 'Not Acceptable')
    self.assertEqual(response.body, ('This DCube server is only capable of '
        'producing media type "application/jsonrequest".'))

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
      'body': None,
      'head': {'status': 405,
        'message': 'Invalid method "post".',
        'authorization': []}})

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
      'body': None,
      'head': {'status': 401,
        'message': 'No authorization credentials.',
        'authorization': []}})

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
      'body': None,
      'head': {'status': 401,
        'message': 'Username "null" is invalid.',
        'authorization': []}})

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
      'body': None,
      'head': {'status': 401,
        'message': 'Username "not_really_aUser" does not exist.',
        'authorization': []}})

    # We start a new session by just sending the username in the credentials.
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

    # nonce and nextnonce are sha1 hashes that we must use to calculate the
    # conce and response to authenticate the next call.
    self.assertEqual(len(json['head']['authorization'][1]), 40)
    self.assertEqual(len(json['head']['authorization'][2]), 40)

    self.assertEqual(json['body'], 'DCube host on Google App Engine')

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

class UserManagement(unittest.TestCase):

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

      * A call to any "/users/" URL does not require CHAP authentication,
        but the information available to unauthenticated requests is limited to
        the "get" DCube method only, and the only data returned is the
        username.

      * CHAP Authenticated calls to any "/users/" URL will allow access to.

      * When a DCube "get" call is made to "/" it simply
      authenticates the user, and if the user authenticates,
      it responds with the host information.

    """

    # HTTP GET method is not allowed in DCube protocol.
    response = test_utils.make_http_request(
        method='GET',
        url='/users/foo_user',
        body=None,
        headers={'User-Agent': 'UA:DCube test :: GET method not allowed'})
    self.assertEqual(response.status, 405)
    self.assertEqual(response.message, 'Method Not Allowed')
    self.assertEqual(response.body, 'HTTP method "GET" is invalid for DCube protocol.')

    # HTTP PUT method is not allowed in DCube protocol.
    response = test_utils.make_http_request(
        method='PUT',
        url='/users/foo_user',
        body=None,
        headers={'User-Agent': 'UA:DCube test :: PUT method not allowed'})
    self.assertEqual(response.status, 405)
    self.assertEqual(response.message, 'Method Not Allowed')
    self.assertEqual(response.body, 'HTTP method "PUT" is invalid for DCube protocol.')

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
      'body': None,
      'head': {'status': 501,
        'message': 'The URL "/users/" is not implemented on this host.',
        'authorization': []}})

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
      'body': None,
      'head': {'status': 404,
        'message': 'User "foo_user" could not be found.',
        'authorization': []}})

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
        'message': 'OK',
        'authorization': []}})

    # A client can get all user data if the user is authenticated.
    response = test_utils.make_http_request(
        method='POST',
        url='/users/%s'% ADMIN_USERNAME,
        body=('{"head":{"method":"get","authorization":["%s"]}}'%
          ADMIN_USERNAME),
        headers={
          'User-Agent': 'UA:DCube test :: get existing user',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 200)
    json = simplejson.loads(response.body)
    self.assertEqual(json['body'], {'username': ADMIN_USERNAME})
    self.assertEqual(json['head']['status'], 200)

