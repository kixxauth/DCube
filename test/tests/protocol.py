import unittest

import test_utils

HOST = test_utils.HOST
LOCAL = test_utils.LOCAL

class Basic(unittest.TestCase):
  def test_not_found(self):
    """## Requesting a URL that does not exist. ##

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
    """## Protocol Documentation ##

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
    """## Basic HTTP calls to the root "/" url. ##

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
        body=None,
        headers={
          'User-Agent': 'UA:DCube test :: invalid Content-Type',
          'Content-Type': 'application/x-www-form-urlencoded'})
    self.assertEqual(response.status, 415)
    self.assertEqual(response.message, 'Unsupported Media Type')
    self.assertEqual(response.body,
        'Content-Type "application/x-www-form-urlencoded" is invalid for JSONRequest protocol.')

    # The Accept header on the request must be application/jsonrequest.
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body=None,
        headers={
          'User-Agent': 'UA:DCube test :: invalid Accept',
          'Accept': 'text/html',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 406)
    self.assertEqual(response.message, 'Not Acceptable')
    self.assertEqual(response.body, ('This DCube server is only capable of '
        'producing media type "application/jsonrequest".'))

    # The body of the request must be valid JSON.
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body='invalid json',
        headers={
          'User-Agent': 'UA:DCube test :: invalid JSON',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 400)
    self.assertEqual(response.message, 'Bad Request')
    self.assertEqual(response.body, ('Invalid JSON text body : (invalid json)'))

    # The body of the request must be a JSON encoded {} object.
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body='[1,2,3]', # Valid JSON, but it's not an {} object.
        headers={
          'User-Agent': 'UA:DCube test :: invalid JSON',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 400)
    self.assertEqual(response.message, 'Bad Request')
    self.assertEqual(response.body, ('Invalid JSON text body : ([1,2,3])'))

    # The JSONRequest body must contain a 'head' attribute that is a dictionary.
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body='{}', # Valid JSON, but no 'head'.
        headers={
          'User-Agent': 'UA:DCube test :: no head',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 400)
    self.assertEqual(response.message, 'Bad Request')
    self.assertEqual(response.body, 'Missing DCube message "head" in ({})')

    # The JSONRequest 'head' attribute must contain an 'method' attribute that
    # is is the name of the function to invoke on this url.
    response = test_utils.make_http_request(
        method='POST',
        url='/',
        body='{"head":{}}', # Valid JSON, but no 'method'.
        headers={
          'User-Agent': 'UA:DCube test :: no authorization',
          'Accept': 'application/jsonrequest',
          'Content-Type': 'application/jsonrequest'})
    self.assertEqual(response.status, 400)
    self.assertEqual(response.message, 'Bad Request')
    self.assertEqual(response.body, 'Missing DCube message header "method" in ({"head":{}})')

  def test_robots(self):
    """## Test the robots.txt call. ##

    DCube also implements a simple robots.txt file for the web crawling bots
    that care to listen.

    """
    response =  test_utils.make_http_request(
        method='GET',
        url='/robots.txt',
        body=None,
        headers={'User-Agent':'UA:DCube tests :: robots.text'})

    self.assertEqual(response.status, 200)
    self.assertEqual(response.headers['content-type'],
                       'text/plain')
    self.assertEqual(response.headers['content-length'], '25')
    self.assertEqual(response.headers['cache-control'],
                     'public')
    self.assertEqual(response.headers['last-modified'],
                     'Fri, 1 Jan 2010 00:00:01 GMT')
    # We can't check the expires header directly because of time skew.
    self.assertEqual(len(response.headers['expires']), 29)
    self.assertEqual(response.body, 'User-agent: *\nDisallow: /') 
