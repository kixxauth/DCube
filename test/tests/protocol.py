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
    def make_req(headers):
      return test_utils.make_http_request(
          'GET',
          '/lost_city_of_atlantis',
          None,
          headers)

    def trivial_checks(response):
      self.assertEqual(response.message, 'Not Found') 
      self.assertEqual(response.headers['content-type'],
                       'application/jsonrequest')
      self.assertEqual(response.headers['cache-control'],
                       'public')
      self.assertEqual(response.headers['last-modified'],
                       'Fri, 1 Jan 2010 00:00:01 GMT')
      # We can't check the expires header directly because of time scews.
      self.assertEqual(len(response.headers['expires']), 29)


    # The accept header is not specified
    response = make_req({'Accept':None,
              'User-Agent':'DCube not found tester :: no-accept',
              'Host': HOST})

    expected_response_body = ("The URL '/lost_city_of_atlantis' "
        "could not be found on the %s host."% HOST)

    self.assertEqual(response.status, 404)
    self.assertEqual(response.body, '"%s"'% expected_response_body) 

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
        'GET',
        '/docs/',
        None,
        {'User-Agent':'DCube get docs tester'})

    self.assertEqual(response.status, 404)

  def test_root(self):
    """## Basic HTTP calls to the root "/" url. ##

    The following HTTP calls to the root
    "http://fireworks-skylight.appspot.com/" url of the DCube api demonstrate
    the trivial utility it provides.
      
      * Like most urls in this protocol, "/" only implements the HTTP "GET"
      method.

      * Also, like most urls in this protocol, "/" adheres to the
      [JSONRequest](http://www.json.org/JSONRequest.html) protocol.

      * "/" only implements the "get" DCube method.

      * A call to "/" requires CHAP authentication.

      * When a DCube "get" call is made to "/" it simply
      authenticates the user, and if the user authenticates,
      it responds with the host information.

    """
    pass

