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

import re
import time

import logging

import http
import jsonrequest
import store
import pychap
import groups

def dispatch(map, request_method, args):
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
  for method, fun in map:
    if request_method == method:
      # Call the function in this tuple and return the results if we have a
      # match, terminating this 'for' loop.
      return fun(*args)

  # If there was no match, return the invalid method message output.
  return jsonrequest.invalid_method_out(dcube_request.head['method'])

def credentials(head):
  """### Parse and validate user credentials. ###

  If the credentials can be parsed and are properly formed, a tuple
  of username, cnonce, response, and message 'OK' is returned.

  Otherwise a tuple of None, None, None, and an output message is returned.

  Args: The head of a DCube request.
  Returns: A tuple of username, cnonce, response, message
  """
  # If the DCube head dictionary does not have an 'authorization' entry, then
  # we asign it an empty list by default. This is to prevent errors later in
  # the program where a list object is expected.
  auth = head.get('authorization') or []
  len_auth = len(auth)

  # Make sure the credentials object is a list with more than 1 entry. If we
  # don't even have a single item in the credentials list, there is nothing
  # more we can do besides return a relevant DCube message.
  if not isinstance(auth, list) or len_auth is 0:
    return None, None, None, 'No authorization credentials.'

  # auth[0] should be the username. If it is not a string, the caller sent an
  # invalid username in the request and we respond with a relevant DCube
  # message.
  if not isinstance(auth[0], basestring):
    return (None, None, None, 'Username \\"%s\\" is invalid.'%
      (auth[0] is None and 'null' or str(auth[0])))

  # If the cnonce and response were not sent on the request, we've done we can
  # do by returning the username.
  if len_auth < 3:
    return (auth[0], None, None, 'OK')

  # auth[1] should be the cnonce and auth[2] should be the response. Both the
  # cnonce and response must be strings. If not, we send back the relevant
  # message for the response.
  if not isinstance(auth[1], basestring):
    return (auth[0], None, None, 'The given cnonce \\"%s\\" is invalid.'%
      (auth[1] is None and 'null' or str(auth[1])))
  if not isinstance(auth[2], basestring):
    return (auth[0], auth[1], None, 'The given response \\"%s\\" is invalid.'%
      (auth[2] is None and 'null' or str(auth[2])))

  # If the username, cnonce, and response are all OK we return them along with
  # the 'OK' message.
  return auth[0], auth[1], auth[2], 'OK'

def check_request_creds(dcube_request):
  """### Get the user if the credentials can be parsed and validated. ###

  A tuple of (None, user) is returned on success, and a tuple of (output, None)
  on failure.

  Args:
    dcbue_request: The DCube request datatype.

  Returns: A tuple of output tuple, user
  """
  # Parse and validage the credentials out of the DCube head we were given.
  username, cnonce, response, msg = credentials(dcube_request.head)
  if msg != 'OK': # Anything other than 'OK' indicates a problem.
    return jsonrequest.message_out(401, msg), None

  # Get the user from the datastore.
  user = store.get_baseuser(username)
  if user is None: # The user does not exist.
    return jsonrequest.no_user_out(username), None

  # If the user exists there is no reason it should not have the nonce and
  # nextnonce attributes.
  assert user.nonce, 'user.nonce is expected to exist!'
  assert user.nextnonce, 'user.nextnonce is expected to exist!'

  # However, the cnonce and response attributes were sent to us by the request
  # user, so we add them as attributes of the 'user type' before returning it.
  user.cnonce = cnonce
  user.response = response

  # Return the user, but no message.
  return None, user 

def authenticate(dcube_request):
  """### Authenticates, updates, and returns a user. ###

  Args:
    dcbue_request: The DCube request datatype.
  Returns:
    A (None, user) tuple on authentication success or a (output, None) tuple on
    failure.
  """
  # Try to get the "user type" object.
  response, user = check_request_creds(dcube_request)
  if user is None: 
    # The user does not exist, and we simply return the output message given to
    # us by check_request_creds().
    return response, None

  if user.cnonce is None or user.response is None:
    # The user exists, but did not send credentials, so we respond with a
    # relevant message.
    return (jsonrequest.authenticate_out(user.username, user.nonce, user.nextnonce),
        None)

  # Use the pychap module to authenticate. If the users credentials are updated
  # by pychap it will call store.put_baseuser() which we passed in as the first
  # parameter to pychap.authenticate.  This process ensures that the new CHAP
  # credentials are persisted to disk and ready for the next request made by
  # this user.
  auth_user = pychap.authenticate(store.put_baseuser, user)
  if not auth_user.authenticated:
    # The user did not authenticate, so we return the relevant output message.
    return (jsonrequest.authenticate_out(
      user.username, auth_user.nonce, auth_user.nextnonce), None)

  # If we made it this far, then everything has gone OK and we return the user.
  return None, auth_user

def jsonrequest_databases_get(request, dbname):
  """Handles DCube "get" requests to the "/databases/" URL path.

  For the JSONRquest MIME type.

  """
  db = store.get_database(dbname)
  if db is None:
    # If the database does not exist, we respond with a DCube 404 message.
    return jsonrequest.message_out(404, 'Database \\"%s\\" could not be found.'% dbname)

  response, user = authenticate(request)
  if user is None:
    # If the user did not authenticate, we just return the name of this
    # database to simply indicate that it does indeed exist.
    # todo: This should send back creds too.
    return jsonrequest.body_out('{"name":"%s"}'% db.name)

  # We make this assignment to account for the fact that the manager_acl list
  # given to us by the datastore may be None instead of a list. The rest of the
  # program, however, depends on a list object.
  managers = db.manager_acl or []
  if user.username in db.owner_acl or user.username in managers:
    # If the user is in the owner or manager ACL for this database, we send
    # them the whole shebang.
    return jsonrequest.out(
        creds=[user.username, user.nonce, user.nextnonce],
        body={'name':db.name,
          'owner_acl':db.owner_acl,
          'manager_acl':db.manager_acl,
          'user_acl':db.user_acl})

  # Otherwise, we only send back the name of this db along with their
  # credentials.
  return jsonrequest.out(
      creds=[user.username, user.nonce, user.nextnonce],
      body={'name':db.name})

def jsonrequest_databases_put(request, dbname):
  """Handles DCube put requests to the "/databases/" URL path.

  For the JSONRquest MIME type.

  """
  response, user = authenticate(request)
  if user is None:
    return response

  # We make this assignment to account for the fact that the user.groups list
  # given to us by the datastore may be None instead of a list. The rest of the
  # program, however, depends on a list object.
  user_groups = user.groups or []

  # Get the database type object from the datastore.
  db = store.get_database(dbname)
  
  if db is None: 
    # If the database does not exist, we have to assume that the caller
    # intended to create a new one by calling the DCube "put" method on this
    # URL. So, we need to make sure the caller is a member of the 'database'
    # permission level group.
    if 'database' not in user_groups:
      return jsonrequest.authorization_out(403,
          'User is forbidden to create or modify a database.',
          user.username, user.nonce, user.nextnonce)

    # Create the new database type object.
    db = type('Database', (object,), {})()
    db.name = dbname
    db.owner_acl = [user.username]
    db = store.put_database(db) # Put it in the datastore and

    # include it in the DCube response body along with the caller's
    # credentials.
    return jsonrequest.out(201, 'Created.',
        creds=[user.username,
               user.nonce,
               user.nextnonce],
        body={
          'name': db.name,
          'owner_acl': db.owner_acl,
          'manager_acl': db.manager_acl,
          'user_acl': db.user_acl})

  # If we made it this far, that means the database exists and the caller
  # intends to modify it.  The first thing we do is check to see if the caller
  # is trying to modify the owner ACL.
  new_owner_acl = request.body.get('owner_acl')
  if isinstance(new_owner_acl, list) and new_owner_acl != db.owner_acl:
    # A user must be a member of the "account_admin" permission level group to
    # modify the owner ACL.
    if 'account_admin' not in user_groups:
      return jsonrequest.authorization_out(403,
          'User is forbidden to modify the owner access list of a database.',
          user.username, user.nonce, user.nextnonce)

    db.owner_acl = new_owner_acl

  # Next, we check to see if the caller is trying to modify the manager ACL.
  new_manager_acl = request.body.get('manager_acl')
  if isinstance(new_manager_acl, list) and new_manager_acl != db.manager_acl:
    # A user must be on the owner ACL or a member of the "account_admin"
    # permission level group to be able to modify the manager ACL.
    if user.username in db.owner_acl or 'account_admin' in user_groups:
      db.manager_acl = new_manager_acl

    else:
      return jsonrequest.authorization_out(403,
          'User is forbidden to modify the manager access list of this database.',
          user.username, user.nonce, user.nextnonce)

  # Last, we check to see if the user is trying to modify the user ACL.
  new_user_acl = request.body.get('user_acl')
  manager_acl = db.manager_acl or []
  if isinstance(new_user_acl, list) and new_user_acl != db.user_acl:
    # The user must be on the owner ACL or the manager ACL, or a member of the
    # "account_admin" permission level group to be able to modify the user ACL.
    if user.username in db.owner_acl or \
        user.username in manager_acl or \
        'account_admin' in user_groups:
      db.user_acl = new_user_acl

    else:
      return jsonrequest.authorization_out(403,
          'User is forbidden to modify the user access list of this database.',
          user.username, user.nonce, user.nextnonce)

  # Put the changes to disk and return the new database representation to the
  # caller.
  db = store.put_database(db)
  return jsonrequest.out(200, 'Updated.',
      creds=[user.username,
             user.nonce,
             user.nextnonce],
      body={
        'name': db.name,
        'owner_acl': db.owner_acl,
        'manager_acl': db.manager_acl,
        'user_acl': db.user_acl})

def jsonrequest_databases_delete(request, dbname):
  """Handles DCube delete requests to the "/databases/" URL path.

  For the JSONRquest MIME type.

  """
  # Get the database type object from the datastore.
  db = store.get_database(dbname)
  if db is None:
    # If it does not exist, this call gets a DCube 404 response.
    return jsonrequest.message_out(404,
        'Database \\"%s\\" could not be found.'% dbname)

  response, user = authenticate(request)
  if user is None:
    return response

  user_groups = user.groups or []

  # A user must be a sys_admin to delete a database.
  if 'sys_admin' not in user_groups:
    return jsonrequest.authorization_out(403,
        'User forbidden to remove a database.',
        user.username, user.nonce, user.nextnonce)

  # Deleting a database is kind of a big deal, so we log it as such.
  logging.critical('Removing database "%s".', dbname)
  store.delete_database(dbname)
  return jsonrequest.message_out(204, 'Deleted database \\"%s\\".'% dbname)

def jsonrequest_databases(request, db_url):
  """Dispatches requests to the "/databases/" URL path.

  For the JSONRquest MIME type.

  """
  # A call to the "/databases/" URL without a database name is pointless.
  if not db_url:
    return jsonrequest.message_out(501,
        'The URL \\"/databases/\\" is not implemented on this host.')

  # Parse and validate the DCube JSONRequest.
  dcube_request, http_out = jsonrequest.load(request)
  if dcube_request is None:
    return http_out

  # Dispatch the request to the proper function, passing in the request type
  # object itself along with the name of the database as it was matched on the
  # reqeust URL path.
  return dispatch([
      ('get', jsonrequest_databases_get),
      ('put', jsonrequest_databases_put),
      ('delete', jsonrequest_databases_delete)],
    dcube_request.head['method'],
    (dcube_request, db_url))

def jsonrequest_users_get(dcube_request, user_url, user):
  """Handles DCube get requests to the "/users/" URL path.

  For the JSONRquest MIME type.

  """
  # If the user does not exist, we send back a DCube 404 response.
  if user is None:
    return jsonrequest.message_out(404,
        'User \\"%s\\" could not be found.'% user_url)

  # In a get request to "/users/" URLs we have to authenticate the user one
  # step at a time instead of just calling the shortcut authenticate()
  # fucntion. We do this to avoid having to get the user from the datastore
  # more that once. Try to get the user type object first.
  response, auth_user = check_request_creds(dcube_request)
  if auth_user is None:
    return jsonrequest.body_out('{"username":"%s"}'% user.username)

  # If the authenticated user did not send creds we send back a response
  # prompting for the required credentials.
  if auth_user.cnonce is None or auth_user.response is None:
    return jsonrequest.out(
        creds=[auth_user.username, auth_user.nonce, auth_user.nextnonce],
        body={'username': user.username})

  # Try to authenticate using the pychap module.
  authenticated_user = pychap.authenticate(store.put_baseuser, auth_user)
  if authenticated_user.authenticated:
    if auth_user.username == user_url or 'user_admin' in auth_user.groups:
      # The user is requesting their own data or the authenticated user is a
      # member of the 'user_admin' group, so we give it all to them.
      return jsonrequest.out(
          creds=[authenticated_user.username,
                 authenticated_user.nonce,
                 authenticated_user.nextnonce],
          body={'username': user.username, 'groups': user.groups})

  # Limited response for no authentication.
  return jsonrequest.out(
      creds=[authenticated_user.username,
             authenticated_user.nonce,
             authenticated_user.nextnonce],
      body={'username': user.username})

def jsonrequest_users_delete(dcube_request, user_url, target_user):
  """Handles DCube delete requests to the "/users/" URL path.

  For the JSONRquest MIME type.

  """
  # If the user does not exist, we send back a DCube 404 response.
  if target_user is None:
    return jsonrequest.message_out(404, 'User \\"%s\\" could not be found.'% user_url)

  # Get the authenticated user.
  response, auth_user = authenticate(dcube_request)
  if auth_user is None:
    return response

  # We never alow a user to delete another user.
  if auth_user.username != user_url:
    return jsonrequest.authorization_out(403, 'Deleting another user is forbidden.',
        auth_user.username, auth_user.nonce, auth_user.nextnonce)

  store.delete_baseuser(user_url) # Get it done.
  return jsonrequest.message_out(204, 'Deleted user \\"%s\\".'% user_url)

def jsonrequest_users_put(dcube_request, user_url, user):
  """Handles DCube put requests to the "/users/" URL path.

  For the JSONRquest MIME type.

  """
  if user is None:
    # If the use does not exist, we assume the caller intended to create a new
    # one.
    user = type('BaseUser', (object,), {})()
    user.username = user_url
    user.groups = ['users']
    new_user = pychap.authenticate(store.put_baseuser, user)
    return jsonrequest.out(status=201, message='Created.',
        creds=[new_user.username,
               new_user.nonce,
               new_user.nextnonce],
        body={'username': new_user.username})

  # Otherwise we assume the caller is trying to update this user's data, so we
  # try to authenticate.
  response, auth_user = authenticate(dcube_request)
  if auth_user is None:
    return response

  # If the caller is updating their own data, we might as well make them one
  # and the same object.
  if auth_user.username == user.username:
    user = auth_user

  # The first thing we need to do is check to see if the caller is trying to
  # update the permission level group membership.
  new_groups = dcube_request.body.get('groups')
  if new_groups != user.groups and isinstance(new_groups, list):

    # Define a functino to use with the builtin 'reduce()' to determine the
    # permission level of the calling user.
    def reduce_level(current_level, group):
      if groups.MAP[group] > current_level:
        current_level = groups.MAP[group]
      return current_level

    level = reduce(reduce_level, auth_user.groups, 0)

    # Once we have the permission level of the calling user, we can then check
    # all of the modifications they have indicated that they want to make.
    for g in new_groups:
      if g in user.groups:
        continue # The user already belongs to this group.
      group_level = groups.MAP.get(g)
      if group_level is None:
        continue # The group does not exist.
      if group_level > level:
        continue # The user does not have permission for this group.
      # Else add the user to the group.
      user.groups.append(g)

  store.put_baseuser(user) # Put it to disk and return it to the caller.
  return jsonrequest.out(status=200, message='Updated.',
      creds=[user.username,
             user.nonce,
             user.nextnonce],
      body={'username': user.username, 'groups': user.groups})

def jsonrequest_users(request, user_url):
  """Dispatches requests to the "/users/" URL path.

  For the JSONRquest MIME type.

  """
  # A call to the "/users/" URL without a username is pointless.
  if not user_url:
    return jsonrequest.message_out(501,
        'The URL \\"/users/\\" is not implemented on this host.')

  # Parse and validate the DCube JSONRequest.
  dcube_request, http_out = jsonrequest.load(request)
  if dcube_request is None:
    return http_out

  # All the handler functions need to get the user from the datastore, so we
  # decided to just do it here all at once.
  user = store.get_baseuser(user_url)

  # Dispatch the method to the correct handler function and return the results.
  return dispatch([
      ('get', jsonrequest_users_get),
      ('put', jsonrequest_users_put),
      ('delete', jsonrequest_users_delete)],
    dcube_request.head['method'],
    (dcube_request, user_url, user))

def jsonrequest_root(request):
  """Handles requests to the root "/" URL.

  For the JSONRquest MIME type.
  Only supports the DCube "get" method.

  """
  # Parse and validate the DCube JSONRequest.
  dcube_request, http_out = jsonrequest.load(request)
  if dcube_request is None:
    return http_out

  # We only handle the DCube "get" method on the "/" URL.
  if dcube_request.head['method'] != 'get':
    return jsonrequest.invalid_method_out(dcube_request.head['method'])

  # This URL is authenticated.
  response, user = authenticate(dcube_request)
  if user is None:
    return response

  return jsonrequest.out(
      creds=[user.username, user.nonce, user.nextnonce],
      body='DCube host on Google App Engine.')

def robots(request):
  """Handles any request to the "/robots.txt" URL."""
  # Just send back a response.
  headers = [
         ('content-type', 'text/plain'),
         ('cache-control', 'public'),
         ('last-modified', 'Fri, 1 Jan 2010 00:00:01 GMT'),
         # Expires in 8 weeks
         ('expires', http.formatdate(time.time() + (604800 * 8)))]
  return 200, headers, 'User-agent: *\nDisallow: /'

MAP = [

    # Root "/" domain url
    (re.compile('^/$'), # Regex to match URL path.
      [
        ('POST', # Matches only the POST HTTP method.
          [
            # Matches only the "application/jsonrequest" MIME type.
            ('application/jsonrequest',
              jsonrequest_root)])]),

    # Database management "/databases/xyz" urls.
    (re.compile('^/databases/(\w*)$'), # Regex to match URL path.
      [
        ('POST', # Matches only the POST HTTP method.
          [
            # Matches only the "application/jsonrequest" MIME type.
            ('application/jsonrequest',
              jsonrequest_databases)])]),

    # User management "/users/xyz" urls.
    (re.compile('^/users/(\w*)$'), # Regex to match URL path.
      [
        ('POST', # Matches only the POST HTTP method.
          [
            # Matches only the "application/jsonrequest" MIME type.
            ('application/jsonrequest',
              jsonrequest_users)])]),

    # Web crawling robots take notice:
    (re.compile('/robots\.txt'), # Regex to match URL path.
      [
        ('GET', # Only handles the 'GET' HTTP method.
          [
            ('*', # Matches all accept MIME types.
              robots)])])
    ]

def handle_method(env, methods, matches):
  """Determines which handler function to call based on the HTTP method."""
  accept = env.get('HTTP_ACCEPT') or ''
  status, headers, body = http.match_mime(
      methods, accept)(http.Request(env), *matches)
  default_headers = {
          # Last-Modified right now
          'Last-Modified': http.formatdate(time.time()),
          # Expire time in the near future
          'Expires': http.formatdate(time.time() + 360)
        }
  headers = http.update_headers(default_headers, headers).items()
  http.out(status, headers, body)

def handle_match(env, map, matches):
  """Checks for regex matches in the handler MAP"""
  req_method = env.get('REQUEST_METHOD')
  # todo: Return 400 response in this case
  assert req_method, 'No HTTP method.'
  methods = http.match_method(map, req_method)
  ((methods is None and
      # Return 'Method Not Alowed' response with a list of allowed methods.
      http.out(405, [('Allow', ','.join([m[0] for m in map]))], '')) or
      
      # Found a handler for the HTTP method.
      handle_method(env, methods, matches))

def main():
  """Cached and called on every request by App Engine."""
  # The os.environs are set on every request made to this server instance
  # running on App Engine. Here, we typecast the os.environs into a dictionary
  # using the utility funtion in our http module.
  env = http.get_environs()

  # The path is the part of the URL after the domain. So, in
  # "http://fireworks-skylight.appspot.com/users/" the path is "/users/".
  path = env.get('PATH_INFO')

  # The path environment variable should always be set.
  # todo: Return 400 response in this case
  assert path, 'No PATH_INFO environment variable.'
  match = http.match_url(MAP, path)

  # Using the <condition> and <function()> or <function()> idiom for short
  # circuit logic here:
  ((match is None and
      # Return 'Not Found' response.
      http.out(404, [
        ('Cache-Control', 'public'),
        # Expires in 8 weeks.
        ('Expires', http.formatdate(time.time() + (604800 * 8)))], '')) or

      # Found a handler for this URL.
      handle_match(env, *match))

# If this is indeed the main process, call the main() function that was just
# defined.
if __name__ == '__main__':
  main()
