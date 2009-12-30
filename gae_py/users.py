import os
import sys
import wsgiref.util
import webob

from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from google.appengine.ext import db
from google.appengine.api import datastore
from google.appengine.api import datastore_errors
from django.utils import simplejson

import re
import logging

class BaseUser(db.Model):
  """The root user data model for a user on this host.

  The BaseUser class contains the meta data we'll need for a user session.

  A BaseUser entity must be put with a key_name key.  The key_name used
  should be the username of the user, and should be URL safe.  Therefore,
  before any user is put(), we need to first check to see if a user already
  exists with the same key_name.

  Currently our BaseUser data model contains properties used for CHAP
  authentication, which is the only quality of protection protocol we currently
  implement. Other datafields may be added to this data model later, or the
  model could be sub-classed.
  """
  # A random nonce string used for authentication during a user session.  The
  # nonce is replaced by nextnonce for every successful request made by this
  # user.
  nonce = db.StringProperty(indexed=False)

  # A random nonce string used for authentication during a user session.  The
  # nonce is replaced by nextnonce for every successful request made by this
  # user.
  nextnonce = db.StringProperty(indexed=False)

  # The response value of an Authorization request is hashed and compared
  # against the passkey value.  If there is a match, the cnonce value of the
  # Authorizationrequest becomes the new passkey.
  passkey = db.StringProperty(indexed=False)

def getBaseUser(username):
  return BaseUser.get_by_key_name('username:%s' % username)

def putBaseUser(username):
  return BaseUser(key_name=('username:%s' % username)).put()

def createJSONResponse(status=200, message='ok', creds=[], body=None):
  return simplejson.dumps(dict(
      head=dict(status=status, message=message, authorization=creds),
      body=body))

class Prototype():
  pass

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

  user = getBaseUser(json_req['head']['authorization'][0])

  handler = None
  groups = ()
  for regexp, handlers in url_mapping:
    match = re.match(regexp, webob_req.path)
    if match:
      handler = handlers.get(json_req['head']['method'])
      if callable(handler):
        groups = match.groups()

        session = Prototype()
        session.status = 200
        session.message = 'ok'
        session.authenticate = []
        session.body = None
        session.username = json_req['head']['authorization'][0]
        session.url = webob_req.path
        session.userExists = user and True or False

        session.store = Prototype()

        def build_createNewUser(this_session):
          def store_createNewUser():
            this_session.status = 201
            this_session.message = ('created user "%s"' %
                putBaseUser(this_session.username).name())

          return store_createNewUser

        session.store.createNewUser = build_createNewUser(session)

        handler(session, *groups)
        response()(createJSONResponse(status=session.status,
                                      message=session.message,
                                      creds=session.authenticate,
                                      body=session.body))
        return True
      else:
        response()(createJSONResponse(status=405,
          message=('"%s" method not allowed' % json_req['head']['method'])))
        return False

  response(status=404)('the url "%s" could not be found on this host.' % webob_req.path)

def users_put_handler(session, user_url):
  if len(user_url) is 0:
    session.status = 403
    session.message = 'access to url "/users/" is forbidden'
    return

  if user_url != session.username:
    session.status = 400
    session.message = 'username "%s" does not match url "%s"' % \
        (session.username, session.url)
    return

  if not session.userExists:
    session.store.createNewUser()
    return

def main():
  constructSession(startResponse, [
    ('/users/(\w*)', {'PUT': users_put_handler})])

if __name__ == '__main__':
  main()
