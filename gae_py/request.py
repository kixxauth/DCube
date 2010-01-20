"""This is the main handler script for App Engine. Requests are directed here
by the handler configuration in app.yaml, starting the main() function on each
request.

The main() function is cached by App Engine, which is an important performance
consideration.  http://code.google.com/appengine/docs/python/runtime.html

The session instance is started by a call to session.start() in main() which is
passed a url mapping list.  The session runner then calls the appropriate
handler function, passing it an object containing the public api to the session
and a factory function for building datastore access functions. The rest of the
arguments passed to the handler functions is simply the unpacked matches made
by the regular expression given in the url mapping list against the current
url.  If a handler function returns False, the call chain will be broken and
the session will end.

This server only accepts HTTP PUT requests that conform to the JSONRequest
specification.  The methods indicated by the url mapping list for the handlers
are not HTTP methods, but methods that conform to the protocol of this DCube
host.
"""
import session # todo: remove

import time
import re
import logging

import toolkit
import gate
import pychap
from django.utils import simplejson

def users_base_handler(this, storeFactory, user_url):
  """Base handler for all calls to a /users/ url.
  """
  if len(user_url) is 0:
    this.status = 403
    this.message = 'access to url "/users/" is forbidden'
    return False

  return True

def users_put_handler(this, storeFactory, user_url):
  """Handles put operations on a /users/ url.
  """
  # catch unwanted guests
  if this.username != user_url and not this.authorized:
    this.status = 401
    this.message = 'authenticate'
    return False

  if not this.userExists:
    # create a new user
    user, nonce, nextnonce = storeFactory('create_new_user')()
    logging.info('Created new user "%s"', this.username)
    this.status = 201
    this.message = 'created new user "%s"' % this.username
    this.authenticate = [this.username, nonce, nextnonce]
    this.body = user
    return True

  # check inputs
  if not this.data:
    this.status = 400
    this.message = 'invalid user data'
    return False

  if this.data.get('username') is None:
    this.status = 400
    this.message = 'user data must include a username'
    return False

  if this.data.get('groups') is None:
    this.status = 400
    this.message = 'user data must include a groups list'
    return False

  # update an existing user
  result = storeFactory('update_public_user')(this.data)
  if not result:
    this.status = 403
    this.message = 'permission denied to update user "%s"' % this.username
    return False

  this.status = 200
  this.message = 'updated user "%s"' % this.username
  this.body, nonce, nextnonce = result

def users_get_handler(this, storeFactory, user_url):
  """Handles get operations on a /users/ url.
  """
  this.body = storeFactory('get_public_user')(user_url)
  if this.body is None:
    this.status = 404
    this.message = 'user "%s" not found' % user_url
    if this.username == user_url:
      this.authenticate = []

def users_delete_handler(this, storeFactory, user_url):
  """Handles delete operations on a /users/ url.
  """
  # catch unwanted guests
  if this.username != user_url:
    this.status = 403
    this.message = 'forbidden'
    return False
  
  if not this.authorized:
    this.status = 401
    this.message = 'authenticate'
    if not this.userExists:
      this.authenticate = []
    return False

  this.authenticate = []
  if this.userExists:
    storeFactory('delete_user')()
    logging.info('Deleted user "%s"', this.username)
  this.message = 'deleted user "%s"' % this.username

def db_base_handler(this, storeFactory, db_url):
  """Base handler for all calls to a /databases/ url.
  """
  if len(db_url) is 0:
    this.status = 403
    this.message = 'access to url "/databases/" is forbidden'
    return False

  return True

def db_put_handler(this, storeFactory, db_url):
  pass

def db_get_handler(this, storeFactory, db_url):
  db = None
  try:
    db = storeFactory('get_db')(db_url)
  except AssertionError, ae:
    logging.error(ae)

  if db is None:
    this.status = 404
    this.message = 'database "%s" not found'% db_url
    return True

def db_delete_handler(this, storeFactory, db_url):
  try:
    storeFactory('delete_db')(db_url)
  except AssertionError, ae:
    logging.error(ae)
  this.status = 204
  this.message = 'deleted database "%s"'% db_url
  return True

def base_handler(this, storeFactory):
  """Base handler for all calls to '/' root domain url.
  """
  this.message = 'DCube: Distributed Discriptive Datastore JSONRequest server.'

def old_main():
  # see the docs for session.start() for more about the url map list.
  session.start([

    ('/users/(\w*)',
      {'PUT': ([users_base_handler, users_put_handler], True),
       'GET': ([users_base_handler, users_get_handler], True),
       'DELETE': ([users_base_handler, users_delete_handler], True)}),

    ('/databases/(\w*)',
      {'PUT': [db_base_handler, db_put_handler],
       'GET': [db_base_handler, db_get_handler],
       'DELETE': [db_base_handler, db_delete_handler]}),

    ('/',
      {'GET': ([base_handler], True)})

    ])

class Response(object):
  def __init__(self, attrs):
    self.__dict__ = attrs

class Session(object):
  def __init__(self, req, log, matches):
    self.req = req
    self.log = log
    self.url_matches = matches

    headers ={
        'content-type': 'application/jsonrequest',
        'cache-control': 'private',
        'last-modified': toolkit.http_date(time.time()),
        'expires': toolkit.http_date(time.time() + 360)}

    self.res = Response({
      'status': 200,
      'headers': headers,
      'body': ''})

  @property
  def toresponse(self):
    return (self.log, self.res.status, self.res.headers, self.res.body)

def jsonrequest(f):
  def wrapper(session):
    """Check and validate basic DCube and JSONRequest protocol."""

    # We only supprt POST requests for the DCube protocol.
    if session.req.method != 'POST':
      session.log['warn'] = 'Invalid HTTP method %s'% session.req.method
      session.res.status = 405
      session.res.headers['content-type'] = 'text/plain'
      session.res.body = ('HTTP method "%s" is invalid for DCube protocol.'%
          session.req.method)
      return

    # We only support the application/jsonrequest media type.
    if session.req.content_type != 'application/jsonrequest':
      session.log['warn'] = ('Invalid request media type %s'%
          session.req.content_type)
      session.res.status = 415
      session.res.headers['content-type'] = 'text/plain'
      session.res.body = ('Content-Type "%s" is invalid for JSONRequest protocol.'%
          session.req.content_type)
      return

    # We are only capable of producing application/jsonrequest output.
    if session.req.headers.get('accept') != 'application/jsonrequest':
      session.log['warn'] = ('Invalid Accept header %s'%
          session.req.headers.get('accept'))
      session.res.status = 406
      session.res.headers['content-type'] = 'text/plain'
      session.res.body = ('This DCube server is only capable of '
        'producing media type "application/jsonrequest".')
      return

    # We only accept valid JSON text in the request body
    json = None
    try:
      json = simplejson.loads(session.req.body)
    except:
      session.log['warn'] = 'invalid JSON'
      session.res.status = 400
      session.res.headers['content-type'] = 'text/plain'
      session.res.body = ('Invalid JSON text body : (%s)'% session.req.body)
      return

    # Only the {} dict object is acceptable as a message payload for the DCube
    # protcol.
    if not isinstance(json, dict):
      session.log['warn'] = 'invalid JSON'
      session.res.status = 400
      session.res.headers['content-type'] = 'text/plain'
      session.res.body = ('Invalid JSON text body : (%s)'% session.req.body)
      return

    # Create the body object according to the DCube protocol.
    if not isinstance(json.get('head'), dict):
      session.log['warn'] = 'missing DCube head'
      session.res.status = 400
      session.res.headers['content-type'] = 'text/plain'
      session.res.body = ('Missing DCube message "head" in (%s)'%
          session.req.body)
      return

    if not isinstance(json['head'].get('method'), basestring):
      session.log['warn'] = 'missing DCube method'
      session.res.status = 400
      session.res.headers['content-type'] = 'text/plain'
      session.res.body = ('Missing DCube message header "method" in (%s)'%
          session.req.body)
      return

    session.log['method'] = json['head']['method']
    session.jsonrequest = json
    session.res.status = 200
    session.res.headers['content-type'] = 'application/jsonrequest'
    f(session) # Moving on now. Passing control back to the original function.

  return wrapper

def dcube_authenticate(session):
  auth = session.jsonrequest['head'].get('authorization') or []

  len_auth = len(auth)
  if not isinstance(auth, list) or len_auth is 0:
    session.log['warn'] = 'no creds'
    session.log['status'] = 401
    session.res.body = toolkit.create_json_response(status=401,
        message='No authorization credentials.')
    return

  username = auth[0]
  if not isinstance(username, basestring):
    if username is None:
      username = 'null'
    else:
      username = str(username)
    session.log['warn'] = 'invalid username'
    session.log['status'] = 401
    session.res.body = toolkit.create_json_response(status=401,
        message='Username "%s" is invalid.'% username)
    return

  chap_user = gate.get_builder(
      'ROOT', ['ROOT'], 'get_chap_user_creds')(username)
  
  if chap_user is None:
    session.log['warn'] = 'auth user does not exist'
    session.log['status'] = 401
    session.res.body = toolkit.create_json_response(status=401,
        message='Username "%s" does not exist.'% username)
    return

  if len_auth != 3:
    chap_user.cnonce = None
    chap_user.response = None
  else:
    chap_user.cnonce = auth[1]
    chap_user.response = auth[2]

  auth_user = pychap.authenticate(gate.get_builder(
      'ROOT', ['ROOT'], 'update_chap_user_creds'), chap_user)
  #logging.warn('auth_status:"%s"', auth_user.message)

  if not auth_user.authenticated:
    session.log['status'] = 401
    session.res.body = toolkit.create_json_response(status=401,
        message='Authenticate.', creds=[username, auth_user.nonce, auth_user.nextnonce])
    return

  session.log['status'] = 200
  return [username, auth_user.nonce, auth_user.nextnonce]

@jsonrequest
def root_url(session):
  creds = dcube_authenticate(session)
  if not creds:
    return

  body = 'DCube host on Google App Engine'
  session.log['status'] = 200
  session.res.body = toolkit.create_json_response(status=200,
      message='OK', creds=creds, body=body)

def robots(session):
  # todo: We should not allow POST or PUT requests to robots.txt
  session.res.headers['content-type'] = 'text/plain'
  session.res.headers['cache-control'] = 'public'
  session.res.headers['last-modified'] = 'Fri, 1 Jan 2010 00:00:01 GMT'
  session.res.headers['expires'] = toolkit.http_date(
      time.time() + (toolkit.WEEK_SECS * 8))
  session.res.body = 'User-agent: *\nDisallow: /'

handler_map = [
    (re.compile('^/$'), root_url),
    (re.compile('^/robots\.txt$'), robots)]

def main():
  req = toolkit.request()
  log = {'user-agent': req.headers['User-Agent']}

  logging.debug('webob content-type: %s', req.content_type)
  logging.debug('content-type header: %s', req.headers.get('content_type'))

  for rx, handler in handler_map:
    m = rx.match(req.path_info)
    if m is not None:
      s = Session(req, log, m.groups())
      handler(s)
      toolkit.send_response(*s.toresponse)
      return

  # From here on out we are handling a 404 Not Found
  headers = {
      'cache-control': 'public',
      'last-modified': 'Fri, 1 Jan 2010 00:00:01 GMT',
      'expires': toolkit.http_date(time.time() + (toolkit.WEEK_SECS * 8))}

  body_str = ("The URL '%s' could not be found on the %s host."%
      (req.path_info, req.host))

  if 'text/plain' in req.accept:
    body_format = '%s'
    headers['content-type'] = 'text/plain'

  elif 'text/html' in req.accept:
    body_format = '<h1>Not Found</h1>\n<p>%s</p>'
    headers['content-type'] = 'text/html'

  else:
    body_format = '"%s"'
    headers['content-type'] = 'application/jsonrequest'

  toolkit.send_response(log, 404, headers, body_format % body_str)


if __name__ == '__main__':
  main()
