import unittest
import tests
import simplejson

URL_USERS = '/users/'

class UsersURL(unittest.TestCase):
  def test_methodNotAllowed(self):
    """/users/: method not allowed"""
    cxn = tests.httpConnection()
    cxn.request(*tests.makeJSONRequest_for_httplib(
      url=URL_USERS, method='post', creds=[tests.USERNAME]))

    response = cxn.getresponse()
    self.assertEqual(response.status, 200)
    tests.checkHeaders(response.getheaders(),
        tests.defaultHeaders(content_length=False))

    json_response = simplejson.loads(response.read())
    self.assertEqual(json_response['head']['status'], 405)
    self.assertEqual(json_response['head']['message'], '"POST" method not allowed')
    self.assertEqual(json_response.get('body'), None)

    cxn.close()

  def test_noUserURL(self):
    """/users/: username not included in url"""
    cxn = tests.httpConnection()
    methods = ['put', 'get', 'delete']

    for m in methods:
      cxn.request(*tests.makeJSONRequest_for_httplib(
        url=URL_USERS, method=m, creds=[tests.USERNAME]))

      response = cxn.getresponse()
      self.assertEqual(response.status, 200)
      tests.checkHeaders(response.getheaders(),
          tests.defaultHeaders(content_length=False))

      json_response = simplejson.loads(response.read())
      self.assertEqual(json_response['head']['status'], 403)
      self.assertEqual(json_response['head']['message'],
                       'access to url "/users/" is forbidden')
      self.assertEqual(json_response.get('body'), None)

    cxn.close()

  def test_usernameNotMatch(self):
    """/users/: username does not match url"""
    cxn = tests.httpConnection()
    methods = ['put', 'get', 'delete']

    for m in methods:
      cxn.request(*tests.makeJSONRequest_for_httplib(
        url=URL_USERS +'foo_bar', method=m, creds=[tests.USERNAME]))

      response = cxn.getresponse()
      self.assertEqual(response.status, 200)
      tests.checkHeaders(response.getheaders(),
          tests.defaultHeaders(content_length=False))

      json_response = simplejson.loads(response.read())
      self.assertEqual(json_response['head']['status'], 400)
      self.assertEqual(json_response['head']['message'],
                       ('username "%s" does not match url "/users/foo_bar"' %
                         tests.USERNAME))
      self.assertEqual(json_response.get('body'), None)

    cxn.close()
