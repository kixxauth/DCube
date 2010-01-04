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
  def __init__(self, val):
    self.value = val
  def __str__(self):
    return repr(self.value)

class Pub():
  pass

class Session():
  def __init__(self):
    env = dict(os.environ)
    env['wsgi.input'] = sys.stdin
    env['wsgi.errors'] = sys.stderr
    env['wsgi.version'] = (1, 0)
    env['wsgi.run_once'] = True
    env['wsgi.url_scheme'] = wsgiref.util.guess_scheme(env)
    env['wsgi.multithread'] = False
    env['wsgi.multiprocess'] = False

    wr = webob.Request(env, charset='utf-8',
        unicode_errors='ignore', decode_param_names=True)

    self.username = None
    self.handlers = None
    self.handler = None
    self.url_groups = None
    self.allow_none_user = False
    self.user_agent = env.get('HTTP_USER_AGENT')
    self.http_method = env.get('REQUEST_METHOD')
    self.content_type = wr.headers.get('Content-Type')
    self.accept = wr.headers.get('Accept')
    self.http_body = wr.body
    self.path = wr.path
    self.auth_user = {'nonce': None, 'nextnonce': None}
    self.user_groups = []

  def checkHandlers(self, url_mapping):
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

    msg = 'the url "%s" could not be found on this host.' % self.path
    self.startResponse(status=404, content_type='text/plain')(msg)
    raise StopSession(msg)

  def buildJSONRequest(self):
    # todo: support other HTTP methods (except PUT and DELETE)
    # JSONRequest protocol only allows GET and POST HTTP methods
    if self.http_method != 'GET' and self.http_method != 'POST':
      msg = 'invalid JSONRequest method %s from user agent %s' % \
          (self.http_method, self.user_agent)
      logging.info(msg)
      self.startResponse(status=405)
      raise StopSession(msg)

    # check content-type request header to meet JSONRequest spec
    if self.content_type != 'application/jsonrequest':
      msg = 'invalid JSONRequest Content-Type %s from user agent %s' % \
          (self.content_type, self.user_agent)
      logging.info(msg)
      self.startResponse(status=400)(msg)
      raise StopSession(msg)

    # check accept request header to meet JSONRequest spec
    if self.accept != 'application/jsonrequest':
      msg = 'invalid JSONRequest Accept header %s from user agent %s' % \
          (self.accept, self.user_agent)
      logging.info(msg)
      self.startResponse(status=406)(msg)
      raise StopSession(msg)

    # load request body JSON
    json_req = None
    try:
      json_req = simplejson.loads(self.http_body)
    except:
      msg = 'invalid JSONRequest body from user agent %s' % self.user_agent
      logging.info(msg)
      self.startResponse(status=400)(msg)
      raise StopSession(msg)

    if not isinstance(json_req, dict):
      msg = 'invalid JSON body'
      self.startResponse()(self.createJSONResponse(status=400, message=msg))
      raise StopSession(msg)

    head = (isinstance(json_req.get('head'), dict) and \
        json_req['head'] or {'method': 'GET', 'authorization': []})

    if not isinstance(head.get('method'), basestring):
      method = (head.get('method') is None) and 'null' or head.get('method')
      msg = 'invalid method "%s"' % method
      self.startResponse()(self.createJSONResponse(status=405,
        message=('invalid method "%s"' % method)))
      raise StopSession(msg)

    auth = head.get('authorization')
    self.json_req = dict(head={'method': head['method'].upper(),
               'authorization': isinstance(auth, list) and auth or []},
         body=json_req.get('body'))

    return self

  def checkMethod(self):
    self.handler = self.handlers.get(self.json_req['head']['method'])

    # The handler object may be a tuple containing optional directives
    if isinstance(self.handler, tuple):
      self.handler, self.allow_none_user = self.handler

    if not isinstance(self.handler, list):
      msg = '"%s" method not allowed' % self.json_req['head']['method']
      self.startResponse()(self.createJSONResponse(status=405, message=msg))
      raise StopSession(msg)

    return self

  def authenticate(self):
    # check for authentication credentials
    if len(self.json_req['head']['authorization']) is 0:
      msg = 'credentials required'
      self.startResponse()(self.createJSONResponse(status=401, message=msg))
      raise StopSession(msg)

    # check the username
    username = self.json_req['head']['authorization'][0]
    if not isinstance(username, basestring):
      username = (username is None) and 'null' or username 
      msg = 'invalid username "%s"' % username
      self.startResponse()(self.createJSONResponse(status=401, message=msg))
      raise StopSession(msg)

    # todo: join with conditional above
    if self.checkUsername(username):
      username = (username is None) and 'null' or username 
      msg = 'invalid username "%s"' % username
      self.startResponse()(self.createJSONResponse(status=401, message=msg))
      raise StopSession(msg)

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

    self.startResponse()(self.createJSONResponse(status=401, message='authenticate',
      creds=[username, auth_user.nonce, auth_user.nextnonce]))
    raise StopSession('authenticate')

  def callHandler(self):
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

    for h in self.handler:
      if not h(pub, get_store_factory, *self.url_groups):
        break

    self.startResponse()(self.createJSONResponse(status=pub.status,
                                  message=pub.message,
                                  creds=pub.authenticate,
                                  body=pub.body))
    return True

  def checkUsername(self, username):
    return re.search('\W', username)

  def startResponse(self, status=200, content_type='application/jsonrequest'):
    return util._start_response(
        ('%d %s' %
          (status, webapp.Response.http_status_message(status))),
        [('Content-Type', content_type), ('expires', '-1')])

  def createJSONResponse(self, status=200, message='ok', creds=[], body=None):
    return simplejson.dumps(dict(
        head=dict(status=status, message=message, authorization=creds),
        body=body))

def start(url_mapping):
  try:
    Session().\
        checkHandlers(url_mapping).\
        buildJSONRequest().\
        checkMethod().\
        authenticate().\
        callHandler()
  except StopSession:
    pass
