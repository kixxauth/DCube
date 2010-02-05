"""## The main handler script. ##

This script handles requests to all URL paths except for the speciality
URLs "/testsetup" and "/environs".  The dispatching of requests to this
script is handled in app.yaml.

This handler script defines a function named main(), so the script and its
global environment will be cached like an imported module. The first request
for the script on a given web server evaluates the script normally. For
subsequent requests, App Engine calls the main() function in the cached
environment.
"""

import time
import os

import logging

import http
import jsonrequest
import pychap
import groups
import store

PathHandler = http.PathHandler
PathMapping = http.PathMapping
SessionStop = http.SessionStop

Database = store.Database
BaseUser = store.BaseUser
PutQuery = store.PutQuery

def datastore(f):
  """### Decorator/wrapping function to provide datastore session access. ###

  A single datastore session (store.Session object) is designed to live and die
  with every request that requires access to the datastore. To help make this
  pattern easier to maintain, this function can be used as a decorator
  (@datastore) to functions that need a datastore session object passed to them
  on invocation.  This wrapper not only constructs a datastore session object,
  but commits it back to the datastore when the function exits.

  ! IMPORTANT: Only one function with the @datastore decorator may be called
  per session.

  """

  def wrapper(*args):
    db_session = store.Session()
    # logging.warn('Started session %s', repr(db_session))
    try:
      f(db_session, *args)
      assert False, \
          'Handler function in @datastore decorator did not raise an exception.'
    finally:
      store.commit(db_session)
  return wrapper

def dispatch(methodmap, request_method, args):
  """### Call a mapped function determined by the method. ###

  Iterates through the given map and calls the requested function, passing it
  the supplied arguments. The value of the called function is returned.

  If no matches to the given method were found an output tuple is returned
  containing the invalid method message.

  Args:
    map: A list of method, function tuples.
    request_method: The request method.
    args: A tuple or list of arguments to pass to the called function.

  Returns: An output tuple.
  """
  # Expand each tuple in the given map parameter and test it for equality
  # against the given request method.
  for method, fun in methodmap:
    if request_method == method:
      # Call the function in this tuple and return the results if we have a
      # match, terminating this 'for' loop.
      return fun(*args)

  # If there was no match, return the invalid method message output.
  jsonrequest.invalid_method_out(map(lambda m: m[0], methodmap))

def authenticate(dcube_request, db_session, failhard=True):
  """### Authenticates, updates, and returns a user. ###

  Args:
    dcube_request: The DCube request (a dcube_types.Request datatype) 

    db_session: The datastore session (a store.Session datatype)

    failhard: Boolean flag. If set to True authenticate() will raise a
      StopSession exception whenever there is a problem validating, retrieving,
      or authenticating the user. If failhard is set to False, authenticate()
      will return None rather than raising a StopSession exception.

  Returns:
    A user object on authentication success.

  Raises:
    A populated StopSession exception on authentication failure.
  """

  ###
  # If the DCube head dictionary does not have an 'authorization' entry, then
  # we asign it an empty list by default. This is to prevent bugs later in
  # the program where a list object is expected.
  auth = dcube_request.head.get('authorization') or []
  len_auth = len(auth)

  # Make sure the credentials object is a list with more than 1 entry. If we
  # don't even have a single item in the credentials list, there is nothing
  # more we can do besides return a relevant DCube message.
  if not isinstance(auth, list) or len_auth is 0:
    if failhard:
      jsonrequest.message_out(401, 'No authorization credentials.')
    else:
      return

  # auth[0] should be the username. If it is not a string, the caller sent an
  # invalid username in the request and we respond with a relevant DCube
  # message.
  if not isinstance(auth[0], basestring):
    if failhard:
      jsonrequest.message_out(401, 'Username \\"%s\\" is invalid.'%
      (auth[0] is None and 'null' or str(auth[0])))
    else:
      return

  username = auth[0]
  # Get the user from the datastore.
  user = store.get(db_session, BaseUser, username)
  if not user.stored: # The user does not exist.
    if failhard:
      jsonrequest.no_user_out(username)
    else:
      return

  # If the user exists there is no reason it should not have the nonce and
  # nextnonce attributes.
  assert user.nonce, 'user.nonce is expected to exist!'
  assert user.nextnonce, 'user.nextnonce is expected to exist!'

  if len_auth == 3:
    # If the user sent the cnonce and response, we need to check those too.
    # auth[1] should be the cnonce and auth[2] should be the response. Both the
    # cnonce and response must be strings. If not, we send back the relevant
    # message for the response.
    if not isinstance(auth[1], basestring):
      if failhard:
        jsonrequest.message_out(401, 'The given cnonce \\"%s\\" is invalid.'%
          (auth[1] is None and 'null' or str(auth[1])))
      else:
        return
    if not isinstance(auth[2], basestring):
      if failhard:
        jsonrequest.message_out(401, 'The given response \\"%s\\" is invalid.'%
        (auth[2] is None and 'null' or str(auth[2])))
      else:
        return
    user.cnonce = auth[1]
    user.response = auth[2]
  else:
    user.cnonce = None
    user.response = None

  # DEBUG
  #logging.warn("CNONCE %s", user.cnonce)
  #logging.warn("RESPONSE %s", user.response)
  # END DEBUG

  # Use the pychap module to authenticate. If the users credentials are updated
  # by pychap it will call store.put_baseuser() which we passed in as the first
  # parameter to pychap.authenticate.  This process ensures that the new CHAP
  # credentials are persisted to disk and ready for the next request made by
  # this user.
  auth_user = pychap.authenticate(store.update, user)
  # DEBUG logging.warn('Auth message: %s', auth_user.message)
  if not auth_user.authenticated:
    # The user did not authenticate, so we return the relevant output message.
    if failhard:
      jsonrequest.authenticate_out(
        user.username, auth_user.nonce, auth_user.nextnonce)

  # If we made it this far, then everything has gone OK and we return the user.
  return auth_user

def databases_query(request, db):
  """Handles DCube "query" method requests to the "/databases/" URL path.

  """
  if not db.stored: 
    # If the database does not exist, we respond with a DCube 404 message.
    jsonrequest.message_out(404, 'Database \\"%s\\" could not be found.'% db.name)

  # Authenticate the user.
  user = authenticate(request, db.session)
  
  if db.user_acl is not None and user.username not in db.user_acl:
    jsonrequest.authorization_out(403, 'This database is restricted.',
        user.username, user.nonce, user.nextnonce)

  if not isinstance(request.body, list):
    jsonrequest.authorization_out(400, 'Query body must be a list.',
        user.username, user.nonce, user.nextnonce)

  response_body = []
  for part in request.body:
    if not isinstance(part, dict):
      jsonrequest.authorization_out(400,
          'Query parts must be dictionary objects.',
          user.username, user.nonce, user.nextnonce)

    action = part.get('action')
    stmts = part.get('statements')
    if not isinstance(stmts, list):
      jsonrequest.authorization_out(400,
          'Query part statements must be a list.',
          user.username, user.nonce, user.nextnonce)

    if action == 'get':
      assert False

    elif action == 'put':
      try:
        entity = store.put(db.session, db.name, stmts)
        response_body.append(
            {'action':'put', 'status':201, 'key':entity.pub_key})
      except AssertionError, ae:
        jsonrequest.authorization_out(400,
            str(ae),
            user.username, user.nonce, user.nextnonce)

    elif action == 'query':
      assert False

    else:
      # The action for this query part was not "get" or "put".
      # We only accept "get" or "put", and inform the caller here.
      action = action is None and 'null' or action
      jsonrequest.authorization_out(400,
          'Allowed actions:get,put,query',
          user.username, user.nonce, user.nextnonce)

  # END LOOP for part in request.body:
  jsonrequest.out(creds=[user.username, user.nonce, user.nextnonce],
      body=response_body)

def databases_get(request, db):
  """Handles DCube "get" requests to the "/databases/" URL path.

  """
  if not db.stored: 
    # If the database does not exist, we respond with a DCube 404 message.
    jsonrequest.message_out(404, 'Database \\"%s\\" could not be found.'% db.name)

  user = authenticate(request, db.session, failhard=False)
  if user is None:
    # If the user does not exist, we just return the name of this database to
    # indicate that it does indeed exist.
    jsonrequest.body_out('{"name":"%s"}'% db.name)

  if not user.authenticated:
    # If the user did not authenticate, we send back the authentication prompt
    # along with some limited info about this database.
    jsonrequest.out(
        creds=[user.username, user.nonce, user.nextnonce],
        body={'name': db_name})

  if user.username in db.owner_acl or user.username in db.manager_acl:
    # If the user is in the owner or manager ACL for this database, we send
    # them the whole shabang.
    jsonrequest.out(
        creds=[user.username, user.nonce, user.nextnonce],
        body={'name':db.name,
          'owner_acl':db.owner_acl,
          'manager_acl':db.manager_acl,
          'user_acl':db.user_acl})

  # Otherwise, we only send back the name of this db along with their
  # credentials.
  jsonrequest.out(
      creds=[user.username, user.nonce, user.nextnonce],
      body={'name':db.name})

def databases_put(request, db):
  """Handles DCube put requests to the "/databases/" URL path.

  """
  user = authenticate(request, db.session)
  
  if not db.stored: 
    # If the database does not exist, we have to assume that the caller
    # intended to create a new one by calling the DCube "put" method on this
    # URL. So, we need to make sure the caller is a member of the 'database'
    # permission level group.
    if 'database' not in user.groups:
      jsonrequest.authorization_out(403,
          'User is forbidden to create or modify a database.',
          user.username, user.nonce, user.nextnonce)

    # Create the new database type object.
    db.owner_acl = [user.username]
    new_db = store.update(db)

    # include it in the DCube response body along with the caller's
    # credentials.
    jsonrequest.out(201, 'Created.',
        creds=[user.username,
               user.nonce,
               user.nextnonce],
        body={
          'name': new_db.name,
          'owner_acl': new_db.owner_acl,
          'manager_acl': new_db.manager_acl,
          'user_acl': new_db.user_acl})

  # If we made it this far, that means the database exists and the caller
  # intends to modify it. But, before we get started we need to make sure the
  # caller sent us a dictionary of attributes for the database.
  if not isinstance(request.body, dict):
    jsonrequest.authorization_out(status=400,
        message='Invalid DCube message body to update database: (%s)',
        username = user.username, nonce=user.nonce, nextnonce=user.nextnonce)
  
  # Next, we check to see if the caller is trying to modify the owner ACL.
  new_owner_acl = request.body.get('owner_acl')
  if isinstance(new_owner_acl, list) and new_owner_acl != db.owner_acl:
    # A user must be a member of the "account_admin" permission level group to
    # modify the owner ACL.
    if 'account_admin' not in user.groups:
      jsonrequest.authorization_out(403,
          'User is forbidden to modify the owner access list of a database.',
          user.username, user.nonce, user.nextnonce)

    db.owner_acl = new_owner_acl

  # Next, we check to see if the caller is trying to modify the manager ACL.
  new_manager_acl = request.body.get('manager_acl')
  if isinstance(new_manager_acl, list) and new_manager_acl != db.manager_acl:
    # A user must be on the owner ACL or a member of the "account_admin"
    # permission level group to be able to modify the manager ACL.
    if user.username in db.owner_acl or 'account_admin' in user.groups:
      db.manager_acl = new_manager_acl

    else:
      jsonrequest.authorization_out(403,
          'User is forbidden to modify the manager access list of this database.',
          user.username, user.nonce, user.nextnonce)

  # Last, we check to see if the user is trying to modify the user ACL.
  new_user_acl = request.body.get('user_acl')
  if (new_user_acl is None or isinstance(new_user_acl, list) and
      new_user_acl != db.user_acl):
    # The user must be on the owner ACL or the manager ACL, or a member of the
    # "account_admin" permission level group to be able to modify the user ACL.
    if user.username in db.owner_acl or \
        user.username in db.manager_acl or \
        'account_admin' in user.groups:
      db.user_acl = new_user_acl

    else:
      jsonrequest.authorization_out(403,
          'User is forbidden to modify the user access list of this database.',
          user.username, user.nonce, user.nextnonce)

  # Put the changes to disk and return the new database representation to the
  # caller.
  store.update(db)
  jsonrequest.out(200, 'Updated.',
      creds=[user.username,
             user.nonce,
             user.nextnonce],
      body={
        'name': db.name,
        'owner_acl': db.owner_acl,
        'manager_acl': db.manager_acl,
        'user_acl': db.user_acl})

def databases_delete(request, db):
  """Handles DCube delete requests to the "/databases/" URL path.

  """
  if not db.stored:
    # If it does not exist, this call gets a DCube 404 response.
    jsonrequest.message_out(404,
        'Database \\"%s\\" could not be found.'% db.name)

  user = authenticate(request, db.session)

  # A user must be a sys_admin to delete a database.
  if 'sys_admin' not in user.groups:
    jsonrequest.authorization_out(403,
        'User forbidden to remove a database.',
        user.username, user.nonce, user.nextnonce)

  # Deleting a database is kind of a big deal, so we log it as such.
  logging.critical('Removing database "%s".', db.name)
  store.delete(db)
  jsonrequest.message_out(204, 'Deleted database \\"%s\\".'% db.name)

def users_get(dcube_request, user_url, target_user):
  """Handles DCube get requests to the "/users/" URL path.

  """
  if not target_user.stored:
    # If the user does not exist, we send back a DCube 404 response.
    jsonrequest.message_out(404,
        'User \\"%s\\" could not be found.'% user_url)

  auth_user = authenticate(dcube_request, target_user.session, failhard=False)
  if auth_user is None:
    # If the authenticated user does not exist, we send back a response with
    # limited data about the target user.
    jsonrequest.body_out('{"username":"%s"}'% target_user.username)

  if not auth_user.authenticated:
    # If the authenticated user did not authenticate we send back a response
    # prompting for the required credentials along with limited data about this
    # user.
    jsonrequest.out(
        creds=[auth_user.username, auth_user.nonce, auth_user.nextnonce],
        body={'username': target_user.username})

  if auth_user.username == user_url or 'user_admin' in auth_user.groups:
    # The user is requesting their own data or the authenticated user is a
    # member of the 'user_admin' group, so we give it all to them.
    jsonrequest.out(
        creds=[auth_user.username,
               auth_user.nonce,
               auth_user.nextnonce],
        body={'username': target_user.username, 'groups': target_user.groups})

  # Limited response for users with restricted permissions.
  jsonrequest.out(
      creds=[auth_user.username,
             auth_user.nonce,
             auth_user.nextnonce],
      body={'username': target_user.username})

def users_delete(dcube_request, user_url, target_user):
  """Handles DCube delete requests to the "/users/" URL path.

  """
  # If the user does not exist, we send back a DCube 404 response.
  if not target_user.stored:
    jsonrequest.message_out(404, 'User \\"%s\\" could not be found.'% user_url)

  # Get the authenticated user.
  auth_user = authenticate(dcube_request, target_user.session)

  # We never alow a user to delete another user.
  if auth_user.username != user_url:
    jsonrequest.authorization_out(403, 'Deleting another user is forbidden.',
        auth_user.username, auth_user.nonce, auth_user.nextnonce)

  store.delete(auth_user)
  jsonrequest.message_out(204, 'Deleted user \\"%s\\".'% user_url)

def users_put(dcube_request, user_url, target_user):
  """Handles DCube put requests to the "/users/" URL path.

  """
  if not target_user.stored:
    # If the use does not exist, we assume the caller intended to create a new
    # one.
    new_user = pychap.authenticate(store.update, target_user)
    jsonrequest.out(status=201, message='Created.',
        creds=[new_user.username,
               new_user.nonce,
               new_user.nextnonce],
        body={'username': new_user.username})

  # Otherwise we assume the caller is trying to update this user's data, so we
  # try to authenticate.
  auth_user = authenticate(dcube_request, target_user.session)

  # It is wrong to assume that we are existing in a magic poney land where all
  # the planets line up prefectly and our programs are bug free.  In this case,
  # if we don't make this seemingly meaningless assigment of one user object to
  # another, then when a user updates their own data, really bad shit happens.
  if auth_user.key == target_user.key:
    target_user = auth_user

  # The first thing we need to do is check to see if the caller is trying to
  # update the permission level group membership.
  new_groups = dcube_request.body.get('groups')
  if new_groups != target_user.groups and isinstance(new_groups, list):
    # Define a function to use with the builtin 'reduce()' to determine the
    # permission level of the calling user.
    def reduce_level(current_level, group):
      if groups.MAP[group] > current_level:
        current_level = groups.MAP[group]
      return current_level

    level = reduce(reduce_level, auth_user.groups, 0)

    # Once we have the permission level of the calling user, we can then check
    # all of the modifications they have indicated that they want to make.
    for g in new_groups:
      if g in target_user.groups:
        continue # The user already belongs to this group.
      group_level = groups.MAP.get(g)
      if group_level is None:
        continue # The group does not exist.
      if group_level > level:
        continue # The user does not have permission for this group.
      # Else add the user to the group.
      target_user.groups.append(g)

  store.update(target_user)
  return jsonrequest.out(status=200, message='Updated.',
      creds=[auth_user.username,
             auth_user.nonce,
             auth_user.nextnonce],
      body={'username': target_user.username, 'groups': target_user.groups})

@datastore
def databases_handler(db_session, request):
  """Dispatches requests to the "/databases/" URL path.

  """
  # A call to the "/databases/" URL without a database name is pointless.
  if request.path_matches is None:
    jsonrequest.message_out(501,
        'The URL \\"/databases/\\" is not implemented on this host.')

  # Parse and validate the DCube JSONRequest.
  # We only support the JSONRequest MIME type for the posted request body.
  dcube_request = jsonrequest.load(request)

  # Get the database type object from the datastore.
  db = store.get(db_session, Database, request.path_matches[0])

  # Dispatch the request to the proper function, passing in the request type
  # object itself along with the name of the database as it was matched on the
  # reqeust URL path.
  dispatch([
      ('get', databases_get),
      ('put', databases_put),
      ('query', databases_query),
      ('delete', databases_delete)],
    dcube_request.head['method'],
    (dcube_request, db))

@datastore
def root_handler(db_session, request):
  """Handles requests to the root "/" URL.

  Only supports the DCube "get" method.

  """
  # Parse and validate the DCube JSONRequest.
  # We only support the JSONRequest MIME type for the posted request body.
  dcube_request = jsonrequest.load(request)

  # We only handle the DCube "get" method on the "/" URL.
  if dcube_request.head['method'] != 'get':
    jsonrequest.invalid_method_out(['get'])

  # This URL is authenticated.
  user = authenticate(dcube_request, db_session)

  jsonrequest.out(
      creds=[user.username, user.nonce, user.nextnonce],
      body='DCube host on Google App Engine.')

@datastore
def users_handler(db_session, request):
  """Dispatches requests to the "/users/" URL path.

  """
  # A call to the "/users/" URL without a username is pointless.
  if request.path_matches is None:
    return jsonrequest.message_out(501,
        'The URL \\"/users/\\" is not implemented on this host.')

  # Parse and validate the DCube JSONRequest.
  dcube_request = jsonrequest.load(request)

  # All the user handler functions need to get the user from the datastore, so
  # we do it here to get it over with.
  user = store.get(db_session, BaseUser, request.path_matches[0])

  # Dispatch the method to the correct handler function, passing it the DCube
  # request object, the name of the user as it was given on the requested URL
  # path, and the user object itself.
  dispatch([
      ('get', users_get),
      ('put', users_put),
      ('delete', users_delete)],
    dcube_request.head['method'],
    (dcube_request, request.path_matches[0], user))

def robots_handler(request):
  """Handles any request to the "/robots.txt" URL."""
  # Just send back a response.
  headers = [
         ('content-type', 'text/plain'),
         ('cache-control', 'public'),
         ('last-modified', 'Fri, 1 Jan 2010 00:00:01 GMT'),
         # Expires in 8 weeks
         ('expires', http.formatdate(time.time() + (604800 * 8)))]
  raise SessionStop(status=200, headers=headers,
      body='User-agent: *\nDisallow: /')

MAPPING = PathMapping()
# Database management "/databases/xyz" urls.
MAPPING.append('/databases/(\w*)', PathHandler([('POST', databases_handler)]))
# Root "/" domain url
MAPPING.append('/', PathHandler([('POST', root_handler)]))
# User management "/users/xyz" urls.
MAPPING.append('/users/(\w*)', PathHandler([('POST', users_handler)]))
# Web crawling robots take notice:
MAPPING.append('/robots\.txt', PathHandler([('GET', robots_handler)]))

def main():
  """Cached and called on every request by App Engine."""
  try:
    http.dispatch_method(http.match_path(MAPPING))
  except SessionStop, httpout:
    http.out(httpout)
    # Extra meta for debugging.
    if os.environ['SERVER_SOFTWARE'].startswith('Development'):
      # dev_appserver only
      try:
        useragent = os.environ['HTTP_USER_AGENT']
      except KeyError:
        useragent = 'no user agent'
      logging.info('User Agent: %s', useragent)
  except Exception, e:
    # Extra meta for debugging.
    logging.exception(e)
    logging.warn('User Agent: %s', os.environ['HTTP_USER_AGENT'])
    http.out(SessionStop(status=500, body='Unexpected server error.'))

# If this is indeed the main process, call the main() function that was just
# defined.
if __name__ == '__main__':
  main()
