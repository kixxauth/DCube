import unittest
import tests

class RobotsTxt(unittest.TestCase):
  def test_robotsTxt(self):
    """Check for the robots.txt file."""
    user_agent = ('Mozilla/5.0 (compatible; '
           'Googlebot/2.1; +http://www.google.com/bot.html)')

    cxn = tests.httpConnection()
    cxn.request('GET', '/robots.txt', None, 
        {'User-Agent': user_agent})
    response = cxn.getresponse()

    self.assertEqual(response.status, 200)
    tests.checkHeaders(response.getheaders(),
        tests.defaultHeaders(content_length='26',
                       content_type='text/plain'))
    cxn.close()

# todo: this should not need to be a JSONRequest
class NotFound(unittest.TestCase):
  def test_notFound(self):
    """Check for not found response."""
    cxn = tests.httpConnection()
    cxn.request(*tests.makeJSONRequest_for_httplib(
          url='/foo', method='get', creds=['foo_man']))
    response = cxn.getresponse()
    self.assertEqual(response.status, 404)
    tests.checkHeaders(response.getheaders(),
        tests.defaultHeaders(content_type='text/plain', content_length=False))
    self.assertEqual(response.read(),
        'the url "/foo" could not be found on this host.')
    cxn.close()

# todo: check other URLs for JSONRequest compatability
class JSONRequest(unittest.TestCase):
  def test_invalidMethods(self):
    """JSONRequest invalid http methods"""
    cxn = tests.httpConnection()
    cxn.request('PUT', '/', 'body to put')
    response = cxn.getresponse()
    self.assertEqual(response.status, 405)
    tests.checkHeaders(response.getheaders(),
        tests.defaultHeaders(content_length='0'))

    cxn.request('DELETE', '/', 'body to put')
    response = cxn.getresponse()
    self.assertEqual(response.status, 405)
    tests.checkHeaders(response.getheaders(),
        tests.defaultHeaders(content_length='0'))

    cxn.close()

  def test_invalidContentTypeHeader(self):
    """JSONRequest invalid content type header"""
    cxn = tests.httpConnection()
    content_type = 'application/x-www-form-urlencoded'
    headers = tests.getJSONRequestHeaders()
    headers['Content-Type'] = content_type
    cxn.request('GET', '/', None, headers)
    response = cxn.getresponse()
    self.assertEqual(response.status, 400)
    tests.checkHeaders(response.getheaders(),
        tests.defaultHeaders(content_length=False))
    self.assertEqual(response.read(),
        ('invalid JSONRequest Content-Type %s from user agent %s' % \
            (content_type, headers['User-Agent'])))
    cxn.close()

  def test_invalidAcceptHeader(self):
    """JSONRequest invalid accept header"""
    cxn = tests.httpConnection()
    accept = 'text/html'
    headers = tests.getJSONRequestHeaders()
    headers['Accept'] = accept 
    cxn.request('POST', '/', None, headers)
    response = cxn.getresponse()
    self.assertEqual(response.status, 406)
    tests.checkHeaders(response.getheaders(),
        tests.defaultHeaders(content_length=False))
    self.assertEqual(response.read(),
        ('invalid JSONRequest Accept header %s from user agent %s' % \
            (accept, headers['User-Agent'])))
    cxn.close()
