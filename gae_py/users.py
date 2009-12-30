import os
import sys
import wsgiref.util
import webob

from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from google.appengine.api import datastore
from django.utils import simplejson

import re
import logging

def createJSONResponse(status=200, message='ok', creds=[], body=None):
  return simplejson.dumps(dict(
      head=dict(status=status, message=message, authorization=creds),
      body=body))

def startResponse(status=200):
  return util._start_response(
      ('%d %s' %
        (status, webapp.Response.http_status_message(status))),
      [('Content-Type', 'application/jsonrequest'), ('expires', '-1')])

def constructSession(response):
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
  jRequest = None
  try:
    jRequest = simplejson.loads(webob_req.body)
  except:
    msg = 'invalid JSONRequest body from user agent %s' % user_agent
    logging.info(msg)
    response(status=400)(msg)
    return False

  if not isinstance(jRequest, dict):
    response()(createJSONResponse(status=400, message='invalid JSON body'))
    return False

  head = (isinstance(jRequest.get('head'), dict) and \
      jRequest['head'] or {'method': 'GET', 'authorization': []})

  jRequest = dict(head={'method': (head.get('method') or 'GET'),
                    'authorization': (head.get('authorization') or [])},
              body=jRequest.get('body'))

  # check for authentication credentials
  if len(jRequest['head']['authorization']) is 0:
    response()(createJSONResponse(status=401, message='credentials required'))
    return False

  # check the username
  if not isinstance(jRequest['head']['authorization'][0], basestring):
    response()(createJSONResponse(status=401,
               message=('invalid username "%s"' % \
                   jRequest['head']['authorization'][0])))
    return False

  if re.search('\W', jRequest['head']['authorization'][0]):
    response()(createJSONResponse(status=401,
               message=('invalid username "%s"' % \
                   jRequest['head']['authorization'][0])))
    return False

  #datastore.Get(datastore.Key.from_path('base_user', name, parent=parent))

def main():
  constructSession(startResponse)

if __name__ == '__main__':
  main()
