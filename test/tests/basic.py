import unittest
import tests
import simplejson

# todo: look into support for OPTIONS, HEAD, TRACE, and CONNECT http methods

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

class NotFound(unittest.TestCase):
  def test_notFound(self):
    """Check for not found response."""
    cxn = tests.httpConnection()
    cxn.request('GET', '/foo')
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

    methods = [
        ('PUT', ['/', '/users/']),
        ('DELETE', ['/', '/users/'])
        ]

    for m, urls in methods:
      for url in urls:
        cxn.request(m, url)
        response = cxn.getresponse()
        self.assertEqual(response.status, 405,
            'method %s, url %s' % (m, url))
        tests.checkHeaders(response.getheaders(),
            tests.defaultHeaders(content_length='0'))

    cxn.close()

  def test_invalidContentTypeHeader(self):
    """JSONRequest invalid content type header"""
    cxn = tests.httpConnection()
    content_type = 'application/x-www-form-urlencoded'
    headers = tests.getJSONRequestHeaders(content_type=content_type)
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
    headers = tests.getJSONRequestHeaders(accept=accept)
    cxn.request('POST', '/', None, headers)
    response = cxn.getresponse()
    self.assertEqual(response.status, 406)
    tests.checkHeaders(response.getheaders(),
        tests.defaultHeaders(content_length=False))
    self.assertEqual(response.read(),
        ('invalid JSONRequest Accept header %s from user agent %s' % \
            (accept, headers['User-Agent'])))
    cxn.close()

  def test_invalidJSONRequestBody(self):
    """JSONRequest invalid JSONRequest body"""
    cxn = tests.httpConnection()
    invalid_json = '{not valid json}'
    headers = tests.getJSONRequestHeaders()

    cxn.request('POST', '/', invalid_json, headers)
    response = cxn.getresponse()
    self.assertEqual(response.status, 400)
    tests.checkHeaders(response.getheaders(),
        tests.defaultHeaders(content_length=False))
    self.assertEqual(response.read(),
        'invalid JSONRequest body from user agent %s' %
            headers['User-Agent'])

    invalid_json = '[1,2,3]'
    cxn.request('POST', '/', invalid_json, headers)
    response = cxn.getresponse()
    self.assertEqual(response.status, 200)
    tests.checkHeaders(response.getheaders(),
        tests.defaultHeaders(content_length=False))
    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 400)
    self.assertEqual(json_response['head']['message'], 'invalid JSON body')
    self.assertEqual(json_response.get('body'), None)

    cxn.close()

  def test_invalids(self):
    """JSONRequest no user authentication creds"""
    cxn = tests.httpConnection()
    headers = tests.getJSONRequestHeaders()

    invalids = [('{"head":{}, "body":null}',
                      'credentials required', 401),
                ('{"head":{"authorization":null,"method":"get"}, "body":null}',
                      'credentials required', 401),
                ('{"head":{"authorization":[],"method":"get"}, "body":null}',
                      'credentials required', 401),
                ('{"head":{"authorization":[null],"method":"get"}, "body":null}',
                      'invalid username "null"', 401),
                ('{"head":{"authorization":[1],"method":"get"}, "body":null}',
                      'invalid username "1"', 401),
                ('{"head":{"authorization":["foo man"],"method":"get"}, "body":null}',
                      'invalid username "foo man"', 401),
                ('{"head":{"authorization":["foo-man"],"method":"get"}, "body":null}',
                      'invalid username "foo-man"', 401),
                ('{"head":{"authorization":["foo_man"],"method":1}, "body":null}',
                      'invalid method "1"', 405),
                ('{"head":{"authorization":["foo_man"],"method":null}, "body":null}',
                      'invalid method "null"', 405)
                    ]

    for json, message, status in invalids:
      cxn.request('POST', '/', json, headers)
      response = cxn.getresponse()
      self.assertEqual(response.status, 200)
      json_response = simplejson.loads(response.read())
      self.assertEqual(json_response['head']['status'], status)
      self.assertEqual(json_response['head']['message'], message)
      self.assertEqual(json_response.get('body'), None)

    cxn.close()
