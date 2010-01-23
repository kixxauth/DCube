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


class Proto(object):
  def __init__(self, attrs):
    self.__dict__ = attrs

class Response(Proto):
  pass

class AuthUser(Proto):
  pass

class DCubeResponse(Proto):
  def update(self, new_attrs):
    self.__dict__.update(new_attrs)

class Session(object):
  def __init__(self, req, log, matches):
    self.req = req
    self.log = log
    self.url_matches = matches

    # todo: headers should be an object that implements a __set__ method that
    # makes content-type, Content-Type, and CONTENT-TYPE all equivalent.
    headers ={
        'content-type': 'text/plain',
        'cache-control': 'private',
        'last-modified': toolkit.http_date(time.time()),
        'expires': toolkit.http_date(time.time() + 360)}

    self.res = Response({
      'status': 200,
      'headers': headers,
      'body': ''})

    self.authuser = AuthUser(
        {'username': None, 'groups': ['users']})
    self.dcube_response = DCubeResponse(
        {'status':200,'message':'OK','creds':[],'body':None})

  @property
  def toresponse(self):
    return (self.log, self.res.status, self.res.headers, self.res.body)

  def datastore_factory(self, interface):
    return gate.get_builder(self.authuser.username,
                         self.authuser.groups, interface)

  def prep_http(self,
      warn='ok',
      status=200,
      headers={},
      body=None):
    """Update the Session object for HTTP output.

    Args:
      warn: The warning message that will go to the request log.
      status: The HTTP status code for the response.
      headers: A dictionary of HTTP headers to add or update in the response.
      body: The content of the HTTP response body.

    """
    self.log['warn'] = warn
    self.res.status = status
    self.res.headers.update(headers)
    self.res.body = body

  def prep_json(self, **kwargs):
    """Update the Sesssion object for outputing a DCube JSON message.

    Args:
      warn: The warning message that will go to the request log.
      status: The DCube message status (not HTTP status)
      message: The DCube status message
      creds: The DCube message authentication credentials.
      body: The DCube message body.

    """
    self.dcube_response.update(kwargs)
    self.log['status'] = self.dcube_response.status # This is the protocol status, not the http status
    self.prep_http(kwargs.get('warn') or 'ok', 200,
        {'content-type':'application/jsonrequest'},
        simplejson.dumps(dict(
          head=dict(status=self.dcube_response.status,
                    message=self.dcube_response.message,
                    authorization=self.dcube_response.creds),
          body=self.dcube_response.body)))

def jsonrequest(f):
  def wrapper(session):
    """Check and validate basic DCube and JSONRequest protocol."""

    # We only supprt POST requests for the DCube protocol.
    if session.req.method != 'POST':
      session.prep_http(
        warn='Invalid HTTP method %s'% session.req.method,
        status=405,
        body=('HTTP method "%s" is invalid for DCube protocol.'%
            session.req.method))
      return

    # We only support the application/jsonrequest media type.
    if session.req.content_type != 'application/jsonrequest':
      session.prep_http(
        warn=('Invalid request media type %s'%
          session.req.content_type),
        status=415,
        body=('Content-Type "%s" is invalid for JSONRequest protocol.'%
          session.req.content_type))
      return

    # We are only capable of producing application/jsonrequest output.
    if session.req.headers.get('accept') != 'application/jsonrequest':
      session.prep_http(
        warn=('Invalid Accept header %s'%
          session.req.headers.get('accept')),
        status=406,
        body=('This DCube server is only capable of '
        'producing media type "application/jsonrequest".'))
      return

    # We only accept valid JSON text in the request body
    json = None
    try:
      json = simplejson.loads(session.req.body)
    except: # todo: What error do we want to catch?
      session.prep_http(
        warn='invalid JSON',
        status=400,
        body=('Invalid JSON text body : (%s)'% session.req.body))
      return

    # Only the {} dict object is acceptable as a message payload for the DCube
    # protcol.
    if not isinstance(json, dict):
      session.prep_http(
        warn='invalid JSON',
        status=400,
        body=('Invalid JSON text body : (%s)'% session.req.body))
      return

    # Create the body object according to the DCube protocol.
    if not isinstance(json.get('head'), dict):
      session.prep_http(
        warn='missing DCube head',
        status=400,
        body=('Missing DCube message "head" in (%s)'%
          session.req.body))
      return

    if not isinstance(json['head'].get('method'), basestring):
      session.prep_http(
        warn='missing DCube method',
        status=400,
        body=('Missing DCube message header "method" in (%s)'%
          session.req.body))
      return

    json['head']['method'] = json['head']['method'].lower()
    session.log['method'] = json['head']['method']
    session.jsonrequest = json
    f(session) # Moving on now. Passing control back to the original function.

  return wrapper

def dcube_authenticate(session):
  auth = session.jsonrequest['head'].get('authorization') or []

  len_auth = len(auth)
  if not isinstance(auth, list) or len_auth is 0:
    session.prep_json(
        warn='no creds',
        status=401,
        message='No authorization credentials.')
    return

  username = auth[0]
  if not isinstance(username, basestring):
    if username is None:
      username = 'null'
    else:
      username = str(username)
    session.prep_json(
        warn='invalid username',
        status=401,
        message='Username "%s" is invalid.'% username)
    return


  session.authuser.groups = gate.get_builder(
      'ROOT', ['ROOT'], 'get_user_groups')(username) or session.authuser.groups
  chap_user = gate.get_builder(
      'ROOT', ['ROOT'], 'get_chap_user_creds')(username)
  
  if chap_user is None:
    session.prep_json(
        warn='auth user does not exist',
        status=401,
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
    session.prep_json(
        warn='auth user not authenticated',
        status=401,
        creds=[username, auth_user.nonce, auth_user.nextnonce],
        message='Authenticate.')
    return

  session.authuser.username = username
  session.prep_json(creds=[username, auth_user.nonce, auth_user.nextnonce])
  return [username, auth_user.nonce, auth_user.nextnonce]

@jsonrequest
def root_url(session):
  if session.jsonrequest['head']['method'] != 'get':
    session.prep_json(
        warn='invalid method',
        status=405,
        message='Invalid method "%s".'% session.jsonrequest['head']['method'])
    return

  creds = dcube_authenticate(session)
  if not creds:
    return

  session.prep_json(creds=creds, body='DCube host on Google App Engine')

@jsonrequest
def users_url(session):
  username = session.url_matches[0]
  if not username:
    session.prep_json(
        warn='cannot access /users/',
        status=501,
        message='The URL "/users/" is not implemented on this host.')
    return

  creds = dcube_authenticate(session)
  user = session.datastore_factory('get_public_user')(username)

  # Implement a DCube "get" message response.
  if session.jsonrequest['head']['method'] == 'get':
    if user is None:
      session.prep_json(
          warn='user not found',
          status=404,
          message='User "%s" could not be found.'% username)
      return

    # A get always returns a 200 OK DCube message.
    session.prep_json(warn='ok', status=200, message='OK', body=user)
    return

  # Implement a DCube "put" message response.
  if session.jsonrequest['head']['method'] == 'put':
    return

  # Implement a DCube "delete" message response.
  if session.jsonrequest['head']['method'] == 'delete':
    return

def robots(session):
  # todo: We should not allow POST or PUT requests to robots.txt
  session.prep_http(
      warn='ok',
      status=200,
      headers={'content-type':'text/plain',
               'cache-control':'public',
               'last-modified':'Fri, 1 Jan 2010 00:00:01 GMT',
               'expires':toolkit.http_date(
                           time.time() + (toolkit.WEEK_SECS * 8))},
      body='User-agent: *\nDisallow: /')

# URL mapping to handler functions using regex
handler_map = [
    (re.compile('^/$'), root_url),
    (re.compile('^/users/(.*)$'), users_url),
    (re.compile('^/robots\.txt$'), robots)]

def main():
  req = toolkit.request()
  log = {'user-agent': req.headers['User-Agent']}

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
