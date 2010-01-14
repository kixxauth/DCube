"""This module provides a session handler api for each request to this DCube host.

All capabilities available to request handlers should go through this session
handler module.

This module is mainly an implementation of the protocol used by this DCube host
for handling JSONRequest communication with DCube clients.

DCube Protocol 1.0
------------------
All HTTP requests made to DCube must conform to the
[JSONRequest][http://www.json.org/JSONRequest.html] specification and must be
HTTP POST requests.

### Request
The JSON text in the request message body must represent a dictionary object of
the following form:
    {
      "head":{"method":"GET | PUT", "authorization":[username, cnonce, response]},
      "body": body_object
    }
Where `username` is a user name string, `cnonce` is client computed nonce
string, `response` is client computed passkey string, and `body_object` is
either a representation of an object to PUT in the datastore or query
instructions for a GET request.

### Response
The JSON text in the response message body must represent a dictionary object
of the following form:
    {
      "head":{
        "status":status_code,
        "message":message_string,
        "authorization":[username, nonce, nextnonce]},
      "body": body_object
    }
Where `username` is a user name string, `nonce` is server computed nonce
string, `nextnonce` is a different server computed nonce string, and
`body_object` is either a representation of objects matched in a qeury, the
representation of an object that was PUT in the datastore, or empty.

### Query (GET request body_object)
The body_object for a datastore query must be included in the JSON text of the
HTTP request message body and must represent a list object of the following
form:
    [
      [attribute_name, filter, value],...
    ]
Where `attribute_name` is the name of the attribute to filter the query on,
`filter` is one of "=", ">", "<", and value is the value to compare against.
Only one attribute in the query is allowed to contain inequality filters.

### Put (PUT request body_object)
The body_object for a put operation to the datastore must be included in the
JSON text of the HTTP request message body and represent an object of the
following form:
    {
      "index":[[attribute_name, value],...],
      "entity": entity_object
    }
Where `attribute_name` is the name of an attribute to index, `value` is a value
to index for `attribute_name`, and `entity_object` is any object that may be
represented by JSON text.
"""
import os
import sys
import re
import wsgiref.util
import webob
import logging

from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from django.utils import simplejson

import gate
import pychap

class StopSession(Exception):
  """Exception class used to explicity end the call chain for a session.
  """
  def __init__(self, val):
    self.value = val
  def __str__(self):
    return repr(self.value)

class Pub():
  """The public session api passed to handler functions. Defined in Session.().
  """
  pass

# todo: Should Session be private?
class Session():
  """The main session handling class. The capabilities of this DCube host are
  all exposed through an instance of this class to the request handler
  functions.
  """
  def __init__(self):
    env = dict(os.environ)
    env['wsgi.input'] = sys.stdin
    env['wsgi.errors'] = sys.stderr
    env['wsgi.version'] = (1, 0)
    env['wsgi.run_once'] = True
    env['wsgi.url_scheme'] = wsgiref.util.guess_scheme(env)
    env['wsgi.multithread'] = False
    env['wsgi.multiprocess'] = False

    self.log = {}

    wr = webob.Request(env, charset='utf-8',
        unicode_errors='ignore', decode_param_names=True)

    self.path = wr.path
    self.http_req_method = env.get('REQUEST_METHOD')
    self.user_agent = env.get('HTTP_USER_AGENT')
    self.req_content_type = wr.headers.get('Content-Type')
    self.req_accept = wr.headers.get('Accept')
    self.http_req_body = wr.body

    self.http_status = 200
    # http_headers should only be accessed through Session.set_http_header()
    self.http_headers = {'CONTENT-TYPE':'application/jsonrequest',
        'CACHE-CONTROL':'private', 'EXPIRES':'-1'}
    self.http_res_body = ''

    self.username = None
    self.handlers = None
    self.handler = None
    self.url_groups = None
    self.allow_none_user = False
    self.auth_user = {'nonce': None, 'nextnonce': None}
    self.user_groups = []

  def checkHandlers(self, url_mapping):
    """Takes a url mapping list and does a regex match operation against the
    current url.

    If no matches are found the HTTP status is set to 404 and a StopSession
    exception is thrown.
    """
    for regexp, handlers in url_mapping:
      if not regexp.startswith('^'):
        regexp = '^' + regexp
      if not regexp.endswith('$'):
        regexp += '$'
      match = re.match(regexp, self.path)
      if match:
        self.handlers = handlers
        self.url_groups = match.groups()
        return self

    self.log['warn'] = 'the url "%s" could not be found on this host.' % self.path
    self.http_res_body = self.log['warn']
    self.http_status = 404
    self.set_http_header('Content-Type', 'text/plain')
    self.sendResponse()
    raise StopSession(self.http_res_body)

  def buildJSONRequest(self):
    """Decode and load the JSON text HTTP message body.
    """
    # todo: Only test for POST
    if self.http_req_method != 'GET' and self.http_req_method != 'POST':
      self.log['warn'] = 'invalid JSONRequest method %s' % self.http_req_method
      self.http_status = 405
      self.sendResponse()
      raise StopSession(self.log['warn'])

    # check content-type request header to meet JSONRequest spec
    if self.req_content_type != 'application/jsonrequest':
      self.log['warn'] = ('invalid JSONRequest Content-Type %s' % 
          self.req_content_type)
      self.http_status = 400
      self.http_res_body = self.log['warn']
      self.sendResponse()
      raise StopSession(self.log['warn'])

    # check accept request header to meet JSONRequest spec
    if self.req_accept != 'application/jsonrequest':
      self.log['warn'] = ('invalid JSONRequest Accept header %s' %
          self.req_accept)
      self.http_status = 406
      self.http_res_body = self.log['warn']
      self.sendResponse()
      raise StopSession(self.log['warn'])

    # load request body JSON
    json_req = None
    try:
      json_req = simplejson.loads(self.http_req_body)
    except:
      self.log['warn'] = 'invalid JSONRequest body'
      self.http_status = 400
      self.http_res_body = self.log['warn']
      self.sendResponse()
      raise StopSession(self.log['warn'])

    if not isinstance(json_req, dict):
      self.log['warn'] = 'invalid JSON body'
      self.http_res_body = self.createJSONResponse(status=400,
          message=self.log['warn'])
      self.sendResponse()
      raise StopSession(self.log['warn'])

    head = (isinstance(json_req.get('head'), dict) and \
        json_req['head'] or {'method': 'GET', 'authorization': []})

    if not isinstance(head.get('method'), basestring):
      method = (head.get('method') is None) and 'null' or head.get('method')
      self.log['warn'] = 'invalid method "%s"' % method
      self.http_res_body = self.createJSONResponse(status=405,
        message=self.log['warn'])
      self.sendResponse()
      raise StopSession(self.log['warn'])

    auth = head.get('authorization')
    self.json_req = dict(head={'method': head['method'].upper(),
               'authorization': isinstance(auth, list) and auth or []},
         body=json_req.get('body'))

    self.log['method'] = head.get('method')

    return self

  def checkMethod(self):
    """Check the RPC method called by the request and act accordingly.
    """
    self.handler = self.handlers.get(self.json_req['head']['method'])

    # The handler object may be a tuple containing optional directives
    if isinstance(self.handler, tuple):
      self.handler, self.allow_none_user = self.handler

    if not isinstance(self.handler, list):
      self.log['warn'] = '"%s" method not allowed' % self.json_req['head']['method']
      self.http_res_body = self.createJSONResponse(status=405, message=self.log['warn'])
      self.sendResponse()
      raise StopSession(self.log['warn'])

    return self

  def authenticate(self):
    """Validate against the authentication protocol and check the credentials
    against the stored credentials for the given user and act accordingly.

    Uses pychap module (pychap.py).
    """
    # check for authentication credentials
    if len(self.json_req['head']['authorization']) is 0:
      self.log['warn'] = 'credentials required'
      self.http_res_body = self.createJSONResponse(status=401, message=self.log['warn'])
      self.sendResponse()
      raise StopSession(self.log['warn'])

    # check the username
    username = self.json_req['head']['authorization'][0]
    if not isinstance(username, basestring) or self.checkUsername(username):
      username = (username is None) and 'null' or username 
      self.log['warn'] = 'invalid username "%s"' % username
      self.http_res_body = self.createJSONResponse(status=401, message=self.log['warn'])
      self.sendResponse()
      raise StopSession(self.log['warn'])

    chap_user = gate.get_builder(
        username, ['ROOT'], 'get_chap_user_creds')()
    chap_user['cnonce'] = None
    chap_user['response'] = None
    try:
      chap_user['cnonce'] = self.json_req['head']['authorization'][1]
    except:
      pass
    try:
      chap_user['response'] = self.json_req['head']['authorization'][2]
    except:
      pass

    self.user_groups = gate.get_builder(
        username, ['ROOT'], 'get_user_groups')()

    auth_user = pychap.authenticate(gate.get_builder(
      username, ['ROOT'], 'update_chap_user_creds'), **chap_user)

    self.username = username
    self.user_exists = (auth_user.message != pychap.USER_NA)
    self.auth_user['nonce'] = auth_user.nonce
    self.auth_user['nextnonce'] = auth_user.nextnonce
    if auth_user.authenticated or \
        (auth_user.message is pychap.USER_NA and self.allow_none_user):
          return self

    self.log['warn'] = 'un-authenticated'
    self.http_res_body = self.createJSONResponse(status=401, message='authenticate',
      creds=[username, auth_user.nonce, auth_user.nextnonce])
    self.sendResponse()
    raise StopSession(self.log['warn'])

  def callHandler(self):
    """Call the directed handler, passing it the proper parameters.
    """
    # A Pub instance is meant implement the session api given to the request
    # handler functions.
    pub = Pub()
    pub.username = self.username
    pub.url = self.path
    pub.userExists = self.user_exists
    pub.authenticate = [
        self.username, self.auth_user['nonce'], self.auth_user['nextnonce']]
    pub.body = None
    pub.status = 200
    pub.message = 'ok'

    def get_store_factory(interface):
      return gate.get_builder(self.username,
                           self.user_groups, interface)

    # todo: Wrap in a try block
    for h in self.handler:
      # A handler can break the call chain by returning False, 0, or None
      if not h(pub, get_store_factory, *self.url_groups):
        break

    # each handler called may modify the Pub object, affecting the JSONResponse
    # output by this call to startResponse()
    self.log['status'] = pub.status
    self.http_res_body = self.createJSONResponse(status=pub.status,
                                  message=pub.message,
                                  creds=pub.authenticate,
                                  body=pub.body)
    self.sendResponse()
    return True

  def checkUsername(self, username):
    """Utility to check for invalid characters in a username.
    """
    return re.search('\W', username)

  def sendResponse(self):
    logging.info('REQUEST %s %d %s',
        (self.log.get('method') or 'na'),
        (self.log.get('status') or 500),
        (self.log.get('warn') or 'ok'))
    util._start_response(
        ('%d %s' %
          (self.http_status, webapp.Response.http_status_message(self.http_status))),
        self.http_headers.items())(self.http_res_body)

  def set_http_header(self, name, value):
    """Use Session.set_http_header() instead of accessing  Session.http_headers directly.

    This prevents making the easy programming error of Session.http_headers['Content-Type'] and
    Session.http_headers['content-type'] pointing to different values.
    """
    self.http_headers[name.upper()] = value

  def createJSONResponse(self, status=200, message='ok', creds=[], body=None):
    """Utility for creating the JSONResponse text for a protocol request.
    """
    return simplejson.dumps(dict(
        head=dict(status=status, message=message, authorization=creds),
        body=body))

def start(url_mapping):
  """Takes a url mapping list and starts a Session instance, taking the appropriate
  actions and calling the defined handler functions.

  args: url_mapping
    A list of url directives.

    Each item in the url mapping list must be a tuple that takes the form:
    (regex, methods)

    The 'methods' directive in each mapping list tuple must be a dictionary
    that takes the form:
    {method_name : handlers}
    NOTE: method_name is not an HTTP method name, but an RPC method name as
    defined by the protocol for this server.

    The 'handlers' directive in each method directive must be a tuple that
    takes the form:
    (handler_functions, authentication_directive)
    Where handler_functions is a list of handler functions that will be called
    in the order given and authentication_directive is boolean indicating the
    authentication level. If the authentication_directive is set to True, then
    access will be given to users that do not yet exist.

    example url_mapping:
      [

        ('/users/(\w*)',
          {'PUT': ([users_base_handler, users_put_handler], True),
           'GET': ([users_base_handler, users_get_handler], True),
           'DELETE': ([users_base_handler, users_delete_handler], True)}),

        ('/',
          {'GET': ([base_handler], True)})

        ]

    In this example a request to /users/foo 'PUT' RPC method would first call
    users_base_handler (with 'foo' as the extra argument) and then
    users_put_handler with the same arguments. Since the authentication
    directive is set to True, users that do not yet exist would be given access
    to the 'PUT' capabilities of this url.
  """
  session = Session()
  try:
    session.\
        checkHandlers(url_mapping).\
        buildJSONRequest().\
        checkMethod().\
        authenticate().\
        callHandler()
  except StopSession:
    pass
  finally:
    pass
