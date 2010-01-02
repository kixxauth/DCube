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
    # todo: check http headers
    cxn.close()
