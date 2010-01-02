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

class Session():
  pass

def createJSONResponse(status=200, message='ok', creds=[], body=None):
  return simplejson.dumps(dict(
      head=dict(status=status, message=message, authorization=creds),
      body=body))

def startResponse(status=200, content_type='application/jsonrequest'):
  return util._start_response(
      ('%d %s' %
        (status, webapp.Response.http_status_message(status))),
      [('Content-Type', content_type), ('expires', '-1')])

def start(url_mapping):
  env = dict(os.environ)
  env['wsgi.input'] = sys.stdin
  env['wsgi.errors'] = sys.stderr
  env['wsgi.version'] = (1, 0)
  env['wsgi.run_once'] = True
  env['wsgi.url_scheme'] = wsgiref.util.guess_scheme(env)
  env['wsgi.multithread'] = False
  env['wsgi.multiprocess'] = False

  webob_req = webob.Request(env, charset='utf-8',
      unicode_errors='ignore', decode_param_names=True)

  user_agent = env.get('HTTP_USER_AGENT')

  # todo: support OPTIONS HTTP method
  # JSONRequest protocol only allows GET and POST HTTP methods
  if env['REQUEST_METHOD'] != 'GET' and env['REQUEST_METHOD'] != 'POST':
    logging.info('invalid JSONRequest method %s from user agent %s',
        env['REQUEST_METHOD'], user_agent)
    startResponse(status=405)
    return False

  # check content-type request header to meet JSONRequest spec
  content_type = webob_req.headers.get('Content-Type')

  if content_type != 'application/jsonrequest':
    msg = 'invalid JSONRequest Content-Type %s from user agent %s' % \
        (content_type, user_agent)
    logging.info(msg)
    startResponse(status=400)(msg)
    return False

  # check accept request header to meet JSONRequest spec
  accept = webob_req.headers.get('Accept')

  if accept != 'application/jsonrequest':
    msg = 'invalid JSONRequest Accept header %s from user agent %s' % \
        (webob_req.headers.get('Accept'), user_agent)
    logging.info(msg)
    startResponse(status=406)(msg)
    return False

  # load request body JSON
  json_req = None
  try:
    json_req = simplejson.loads(webob_req.body)
  except:
    msg = 'invalid JSONRequest body from user agent %s' % user_agent
    logging.info(msg)
    startResponse(status=400)(msg)
    return False

  if not isinstance(json_req, dict):
    startResponse()(createJSONResponse(status=400, message='invalid JSON body'))
    return False

  head = (isinstance(json_req.get('head'), dict) and \
      json_req['head'] or {'method': 'GET', 'authorization': []})

  if not isinstance(head.get('method'), basestring):
    method = (head.get('method') is None) and 'null' or head.get('method')
    startResponse()(createJSONResponse(status=405,
      message=('invalid method "%s"' % method)))
    return False

  json_req = dict(head={'method': head['method'].upper(),
                    'authorization': (head.get('authorization') or [])},
              body=json_req.get('body'))

  # check for authentication credentials
  if len(json_req['head']['authorization']) is 0:
    startResponse()(createJSONResponse(status=401, message='credentials required'))
    return False

  # check the username
  username = json_req['head']['authorization'][0]
  if not isinstance(username, basestring):
    username = (username is None) and 'null' or username 
    startResponse()(createJSONResponse(status=401,
               message=('invalid username "%s"' % \
                   username)))
    return False

  if re.search('\W', username):
    startResponse()(createJSONResponse(status=401,
               message=('invalid username "%s"' % \
                   username)))
    return False

  chap_user = gate.get_builder(
      username, ['ROOT'], 'get_chap_user_creds')()
  chap_user['cnonce'] = None
  chap_user['response'] = None
  try:
    chap_user['cnonce'] = json_req['head']['authorization'][1]
  except:
    pass
  try:
    chap_user['response'] = json_req['head']['authorization'][2]
  except:
    pass

  user_groups = gate.get_builder(
      username, ['ROOT'], 'get_user_groups')()

  handler = None
  url_groups = ()
  for regexp, handlers in url_mapping:
    match = re.match(regexp, webob_req.path)
    if match:
      handler = handlers.get(json_req['head']['method'])

      # The handler object may be a tuple containing optional directives
      allow_none_user = False
      if isinstance(handler, tuple):
        allow_none_user = handler[1]
        handler = handler[0]

      if isinstance(handler, list):
        url_groups = match.groups()

        auth_user = pychap.authenticate(gate.get_builder(
          username, ['ROOT'], 'update_chap_user_creds'), **chap_user)

        session = Session()
        session.username = username
        session.url = webob_req.path
        session.userExists = (auth_user.message != pychap.USER_NA)
        session.authenticate = [username, auth_user.nonce, auth_user.nextnonce]
        session.body = None

        if auth_user.authenticated or \
            (not session.userExists and allow_none_user):
          session.status = 200
          session.message = 'ok'

          def get_store_factory(interface):
            return gate.get_builder(username,
                                 user_groups, interface)

          for h in handler:
            if not h(session, get_store_factory, *url_groups):
              break

        else:
          session.status = 401
          session.message = 'authenticate'

        startResponse()(createJSONResponse(status=session.status,
                                      message=session.message,
                                      creds=session.authenticate,
                                      body=session.body))
        return True
      else:
        startResponse()(createJSONResponse(status=405,
          message=('"%s" method not allowed' % json_req['head']['method'])))
        return False

  startResponse(status=404, content_type='text/plain')(
      'the url "%s" could not be found on this host.' % webob_req.path)
