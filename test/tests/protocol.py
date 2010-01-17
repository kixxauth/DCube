import unittest

import test_utils

HOST = test_utils.HOST

class Basic(unittest.TestCase):
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
        {'User-Agent':'DCube protocol tester'})

    self.assertEqual(response.status, 404)
    self.assertEqual(response.message, 'Not Found') 
    self.assertEqual(response.body,
        'The url "/docs/" could not be found on the %s host.'% HOST) 

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

