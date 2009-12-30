import os
import sys
import wsgiref.util
import webob

from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from google.appengine.api import datastore
from google.appengine.api import datastore_errors
from django.utils import simplejson

import re
import logging

class Session():
  def __init__(self):
    pass

def createJSONResponse(status=200, message='ok', creds=[], body=None):
  return simplejson.dumps(dict(
      head=dict(status=status, message=message, authorization=creds),
      body=body))

def startResponse(status=200):
  return util._start_response(
      ('%d %s' %
        (status, webapp.Response.http_status_message(status))),
      [('Content-Type', 'application/jsonrequest'), ('expires', '-1')])

def constructSession(response, url_mapping):
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
    response(status=405)
    return False

  # check content-type request header to meet JSONRequest spec
  content_type = webob_req.headers.get('Content-Type')

  if content_type != 'application/jsonrequest':
    msg = 'invalid JSONRequest Content-Type %s from user agent %s' % \
        (content_type, user_agent)
    logging.info(msg)
    response(status=400)(msg)
    return False

  # check accept request header to meet JSONRequest spec
  accept = webob_req.headers.get('Accept')

  if accept != 'application/jsonrequest':
    msg = 'invalid JSONRequest Accept header %s from user agent %s' % \
        (content_type, user_agent)
    logging.info(msg)
    response(status=406)(msg)
    return False

  # load request body JSON
  json_req = None
  try:
    json_req = simplejson.loads(webob_req.body)
  except:
    msg = 'invalid JSONRequest body from user agent %s' % user_agent
    logging.info(msg)
    response(status=400)(msg)
    return False

  if not isinstance(json_req, dict):
    response()(createJSONResponse(status=400, message='invalid JSON body'))
    return False

  head = (isinstance(json_req.get('head'), dict) and \
      json_req['head'] or {'method': 'GET', 'authorization': []})

  if not isinstance(head.get('method'), basestring):
    response()(createJSONResponse(status=405,
      message=('invalid method "%s"' % head.get('method'))))
    return False

  json_req = dict(head={'method': head['method'].upper(),
                    'authorization': (head.get('authorization') or [])},
              body=json_req.get('body'))

  # check for authentication credentials
  if len(json_req['head']['authorization']) is 0:
    response()(createJSONResponse(status=401, message='credentials required'))
    return False

  # check the username
  if not isinstance(json_req['head']['authorization'][0], basestring):
    response()(createJSONResponse(status=401,
               message=('invalid username "%s"' % \
                   json_req['head']['authorization'][0])))
    return False

  if re.search('\W', json_req['head']['authorization'][0]):
    response()(createJSONResponse(status=401,
               message=('invalid username "%s"' % \
                   json_req['head']['authorization'][0])))
    return False

  user = None
  try:
    user = datastore.Get(datastore.Key.from_path('base_user',
      'username:'+ json_req['head']['authorization'][0]))
  except datastore_errors.EntityNotFoundError:
    pass

  handler = None
  groups = ()
  logging.debug('path "%s"', webob_req.path)
  for regexp, handlers in url_mapping:
    logging.debug('regex "%s"', regexp)
    match = re.match(regexp, webob_req.path)
    if match:
      logging.debug('jsonr method "%s"', json_req['head']['method'])
      handler = handlers.get(json_req['head']['method'])
      if callable(handler):
        groups = match.groups()
        handler(Session(), *groups)
        return True
      else:
        response()(createJSONResponse(status=405,
          message=('"%s" method not allowed' % json_req['head']['method'])))
        return False

  response(status=404)('the url "%s" could not be found on this host.' % webob_req.path)

def users_put_handler():
  pass

def main():
  constructSession(startResponse, [
    ('/users/(\w*)', {'put': users_put_handler})])

if __name__ == '__main__':
  main()
