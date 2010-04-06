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
import re

import logging

# Used to format date values for HTTP headers.
from rfc822 import formatdate

from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from google.appengine.ext import db
from django.utils import simplejson

import pychap
import groups
import store

Database = store.Database
BaseUser = store.BaseUser
GeneralData = store.GeneralData

class StopSession(Exception):
  """Exception thrown to stop the current request session.

  This Exception class is meant to be subclassed.

  """

  def __init__(self, msg):
    """Constructor for a StopSession exception type.
    
    Args:
      msg: The message meant to output for the request session.

    """
    self.message = msg

class AuthenticationError(StopSession):
  """Raised when an exception occured while authenticating user credentials.

  """
  status = 401

class Authenticate(StopSession):
  """Raised when a user needs to send additional credentials."""
  status = 401
  message = 'Authenticate.'
  def __init__(self, *creds):
    self.credentials = creds 

class QuerySyntaxError(StopSession):
  """For a syntax error in the database query syntax of a request."""
  status = 400

def authenticate(creds):
  """Take the CHAP credentials of a user and try to authenticate.

  Args:
    creds: A list of credentials: username, cnonce, response
  Returns:
    A list of username, nonce, and nextnonce if the user authenticates.

  Raises:
    AuthenticationError: If the credentials are invalid.
    Authenticate: If the credentials are incomplete or the response does not
    match the stored passkey.

  """

  # If the DCube head dictionary does not have an 'authorization' entry, then
  # we asign it an empty list by default. This is to prevent bugs later in
  # the program where a list object is expected.
  creds = creds or []

  # Make sure the credentials object is a list with more than 1 entry. If we
  # don't even have a single item in the credentials list, there is nothing
  # more we can do besides return a relevant DCube message.
  if not isinstance(creds, list) or len(creds) is 0:
    raise AuthenticationError('No authorization credentials.')

  # auth[0] should be the username. If it is not a string, the caller sent an
  # invalid username in the request and we respond with a relevant DCube
  # message.
  if not isinstance(creds[0], basestring):
    raise AuthenticationError('Username \\"%s\\" is invalid.'%
      (creds[0] is None and 'null' or str(creds[0])))
  username = creds[0]
  # Get the user from the datastore.
  user = BaseUser.get(username)
  if user is None: # The user does not exist.
    raise AuthenticationError('Username \\"%s\\" does not exist.'% username)

  # If the user exists there is no reason it should not have the nonce and
  # nextnonce attributes.
  assert user.nonce, ('%s user.nonce is expected to exist! (%s)'%
      (username, user.nonce))
  assert user.nextnonce, ('%s user.nextnonce is expected to exist! (%s)'%
      (username, user.nextnonce))

  user.cnonce = None
  user.response = None
  if len(creds) == 3:
    # If the user sent the cnonce and response, we need to check those too.
    # auth[1] should be the cnonce and auth[2] should be the response. Both the
    # cnonce and response must be strings. If not, we send back the relevant
    # message for the response.
    if not isinstance(creds[1], basestring):
      raise AuthenticationError('The given cnonce \\"%s\\" is invalid.'%
          (creds[1] is None and 'null' or str(creds[1])))
    if not isinstance(creds[2], basestring):
      raise AuthenticationError('The given response \\"%s\\" is invalid.'%
          (creds[2] is None and 'null' or str(creds[2])))
    user.cnonce = creds[1]
    user.response = creds[2]

  # Use the pychap module to authenticate. If the users credentials are
  # updated by pychap it will call store.put(). This process ensures that the
  # new CHAP credentials are persisted to disk and ready for the next request
  # made by this user.
  auth_user = pychap.authenticate(store.put_user, user)
  # DEBUG logging.warn('Auth message: %s', auth_user.message)
  if not auth_user.authenticated:
    # The user did not authenticate, so we return the relevant output message.
    raise Authenticate(
        user.username, auth_user.nonce, auth_user.nextnonce)

  # If we made it this far, then everything has gone OK and we return the user
  # credentials..
  return [auth_user.username, auth_user.nonce, auth_user.nextnonce]

def normalize_query_statements(stmts, keywords=[], query=False):
  """Validate and normalizing database query statements.

  Args:
    stmts:
      A list of database query statements. Each statement in the list should
      itself be a list of 3 elements.
    keywords:
      A list of keywords to look for in the given statements.
    query:
      A boolean flag to indicate if the return value should be formatted for a
      query or not. If so, then the index list (the second half of the returned
      tuple) is formatted to be used with the GAE method Query.filter().

  Returns:
    A tuple of two items. The first item is a dict of the given keywords, and
    the second is a list of tuples representing the index properties of the
    query.

  Raises:
    AssertionError on invalid query syntax.
  
  """
  named_props = {}
  index_list = []
  for s in stmts:
    assert isinstance(s, list), \
        'Query put action statements must be lists.'
    assert len(s) == 3, \
        'Query put action statements must contain 3 tokens.'
    assert isinstance(s[0], basestring), \
        'The first token in an action statement must be a string.'

    if s[0] in keywords:
      named_props[s[0]] = s[2]
    else:
      if s[2] == []:
        s[2] = None
      index_list.append((query and
        ('%s %s'%('idx_'+ str(s[0]), s[1]), s[2])) or (s[0], s[2]))
  return (named_props, index_list)

def apply_general_data(dbname):
  """Return a function that will convert an GeneralData entity to a dictionary.

  The returned function is designed to be used with map() to build a list of
  valid query results for response output.

  Args:
    dbname: The name of the database to operate on.
  """
  def convert_general_data(entity):
    rv = {'key': entity.key_name(dbname), 'entity': entity.text_body}
    for p in entity.dynamic_properties():
      rv[p.replace('idx_', '', 1)] = getattr(entity, p)
    return rv

  return convert_general_data

def apply_query_action(dbname):
  """Return a function that will execute a query and return the result.

  The returned function is desinged to be used with map() to execute a series
  of query request parts.

  Args:
    dbname: The name of the database to operate on.
  """
  def query_action(part):
    if not isinstance(part, dict):
      raise QuerySyntaxError('Query parts must be dictionary objects.')

    action = part.get('action')
    stmts = part.get('statements')
    if not isinstance(stmts, list):
      raise QuerySyntaxError('Query part:statements must be a list.')

    if action == 'get':
      try:
        t = normalize_query_statements(stmts, ['key'])
      except AssertionError, ae:
        # TODO: By raising an exception here, we are telling the client that we
        # aborted ALL the requested operations, when in fact we have only
        # aborted this one, but commited all previous operations.
        raise QuerySyntaxError(str(ae))

      part_response = {'action': 'get', 'key':None}
      key = str(t[0].get('key'))
      if key is None:
        part_response['status'] = 400
        return part_response

      part_response['key'] = key
      entity = GeneralData.get((dbname, key))
      if entity is None:
        part_response['status'] = 404
        return part_response

      part_response['entity'] = entity.text_body
      part_response['indexes'] = {}
      for p in entity.dynamic_properties():
        part_response['indexes'][p.replace('idx_', '', 1)] = getattr(entity, p)

      part_response['status'] = 200
      return part_response

    elif action == 'put':
      try:
        named_props, indexes = normalize_query_statements(
            stmts, ['key','entity'])
      except AssertionError, ae:
        # TODO: By raising an exception here, we are telling the client that we
        # aborted ALL the requested operations, when in fact we have only
        # aborted this one, but commited all previous operations.
        raise QuerySyntaxError(str(ae))

      part_response = {'action': 'put', 'key':None}
      key = str(named_props.get('key'))
      if key is None:
        part_response['status'] = 400
        return part_response
      part_response['key'] = key
      body = named_props.get('entity')
      entity = GeneralData.get((dbname, key))
      if entity is None:
        part_response['status'] = 201
        entity = GeneralData((dbname, key))
      else:
        part_response['status'] = 200
      for p, v in indexes:
        setattr(entity, 'idx_'+ str(p), v)
      entity.text_body = body
      
      entity.put()
      return part_response

    elif action == 'delete':
      try:
        t = normalize_query_statements(stmts, ['key'])
      except AssertionError, ae:
        # TODO: By raising an exception here, we are telling the client that we
        # aborted ALL the requested operations, when in fact we have only
        # aborted this one, but commited all previous operations.
        raise QuerySyntaxError(str(ae))

      part_response = {'action': 'delete', 'key':None}
      key = t[0].get('key')
      if key is None:
        part_response['status'] = 400
        return part_respons

      part_response['key'] = key
      entity = GeneralData.get((dbname, key))
      if entity is None:
        part_response['status'] = 404
        return part_response

      entity.delete()
      part_response['status'] = 204
      return part_response

    elif action == 'query':
      try:
        named, clauses = normalize_query_statements(stmts, query=True)
      except AssertionError, ae:
        # TODO: By raising an exception here, we are telling the client that we
        # aborted ALL the requested operations, when in fact we have only
        # aborted this one, but commited all previous operations.
        raise QuerySyntaxError(str(ae))

      part_response = {'action': 'query', 'status': 404}
      # DEBUG
      # logging.warn('INDEXES %s', clauses)
      query = db.Query(GeneralData)
      for clause, value in clauses:
        query.filter(clause, value)
      results = query.fetch(500)
      # DEBUG
      # logging.warn('RESULTS %s', results)
      if not len(results):
        return part_response
      part_response['status'] = 200
      part_response['results'] = map(apply_general_data(dbname), results)
      return part_response

    else:
      # The action for this query part was not "get", "delete", "query" or "put".
      raise QuerySyntaxError('Allowed actions:get,put,delete,query')
      # TODO: By raising an exception here, we are telling the client that we
      # aborted ALL the requested operations, when in fact we have only
      # aborted this one, but commited all previous operations.

  return query_action


class BaseHandler(webapp.RequestHandler):
  """Simply exists to override the RequestHandler.error() method."""
  def error(self, code):
    """Catch HTTP 405 codes and set the appropriate 'Allow' header.  """
    if code == 405:
      self.response.set_status(405)
      self.response.headers['allow'] = self._allow
    else:
      self.response.set_status(code)
      self.response.clear()

class JsonRequestHandler(BaseHandler):
  """Dispatch JSONRequests to DCube method specific handlers.

  This handler class should be subclassed by the DCube handler classes.

  This handler only handles the HTTP "POST" method.  It parses and validates
  the incoming DCube message in JSONRequest format, and then dispatches it to
  the proper handler.
  """
  _allow = 'POST'

  def httpout(self, body):
    """Send back an HTTP 200 response."""
    self.response.set_status(200)
    self.response.headers['content-type'] = 'application/jsonrequest'
    self.response.out.write(body)

  def message_out(self, status, message):
    """Send out the status and message parts of a JSON response."""
    self.httpout('{"head":{"status":%d,"message":"%s"}}'% (status, message))

  def authenticate_out(self, status, message, username, nonce, nextnonce):
    """Just send back the DCube authorization header with status and message."""
    self.httpout('{"head":{"status":%d,"message":"%s",'
        '"authorization":["%s","%s","%s"]}}'%
        (status, message, username, nonce, nextnonce))

  def body_out(self, body):
    """Send out a DCube 200 status message with only the body."""
    self.httpout('{"head":{"status":200,"message":"OK"},"body":%s}'% body)

  def out(self, status=200, message='OK', creds=[], body=None):
    """Send out a full DCube response in JSONRequest format."""
    self.httpout(simplejson.dumps(dict(
      head=dict(status=status,
                message=message,
                authorization=creds),
      body=body)))

  def post(self, *matches):
    """Handle the HTTP "POST" method to a URL on this server.

    This dispatcher function automagically handles AuthenticationError and
    Authenticate type exceptions.
    
    """
    # For debugging:
    logging.info('USER_AGENT %s', self.request.user_agent)

    # The "Content-Type" header on the request must be application/jsonrequest.
    if not re.search('^application/jsonrequest', self.request.content_type):
      self.response.set_status(415)
      return

    # We only accept valid JSON text in the request body
    json = None
    try:
      json = simplejson.loads(self.request.body)
    except: # TODO: What error do we want to catch?
      self.out(400, 'Invalid JSON text body : (%s)'% self.request.body)
      return

    # Only the {} dict object is acceptable as a message payload for the DCube
    # protcol.
    if not isinstance(json, dict):
      self.out(400, 'Invalid JSON text body : (%s)'% self.request.body)
      return

    # The head of the request must be a dictionary.
    if not isinstance(json.get('head'), dict):
      self.out(400, 'Missing DCube message "head" in (%s)'% self.request.body)
      return

    # The head must contain a method entry.
    if not isinstance(json['head'].get('method'), basestring):
      self.out(400, 'Missing DCube message header "method" in (%s)'% self.request.body)
      return

    method = json['head']['method']
    if method not in self.dcube_methods:
      self.message_out(405, 'Allowed:%s'% ','.join(self.dcube_methods))
      return
    try:
      # Send the request to the proper handler function.
      if method == 'query':
        self.d3_query(json.get('body'), json['head'].get('authorization'), *matches)
      elif method == 'get':
        self.d3_get(json.get('body'), json['head'].get('authorization'), *matches)
      elif method == 'put':
        self.d3_put(json.get('body'), json['head'].get('authorization'), *matches)
      elif method == 'delete':
        self.d3_delete(json.get('body'), json['head'].get('authorization'), *matches)
      else:
        # TODO: Handle this exception.
        assert False, 'Method "%s" not implemented.'% method
    except AuthenticationError, auth_e:
      self.message_out(auth_e.status, auth_e.message)
    except Authenticate, auth:
      self.authenticate_out(auth.status, auth.message, *auth.credentials)

class DatabasesHandler(JsonRequestHandler):
  """Handle DCube requests to a "/databases/xyz" URL."""
  dcube_methods = ['get','put','delete','query']

  def d3_query(self, request, credentials, match):
    # A call to the "/databases/" URL without a database path name is pointless.
    if not match: # match could be ''
      return self.message_out(501,
          'The URL \\"/databases/\\" is not implemented on this host.')

    db = Database.get(match)
    if db is None: 
      # If the database does not exist, we respond with a DCube 404 message.
      return self.message_out(404, 'Database \\"%s\\" could not be found.'% match)

    # Authenticate the user.
    creds = authenticate(credentials)
    user = BaseUser.get(creds[0])
    
    if db.user_acl and user.username not in db.user_acl:
      return self.authenticate_out(403, 'This database is restricted.', *creds)

    if not isinstance(request, list):
      return self.authenticate_out(400, 'Query body must be a list.', *creds)

    map_action = apply_query_action(db.name)
    try:
      response_body = map(map_action, request)
    except QuerySyntaxError, e:
      return self.authenticate_out(e.status, e.message, *creds)

    self.out(creds=[user.username, user.nonce, user.nextnonce],
        body=response_body)

  def d3_get(self, request, credentials, match):
    # A call to the "/databases/" URL without a database path name is pointless.
    if not match: # match could be ''
      return self.message_out(501,
          'The URL \\"/databases/\\" is not implemented on this host.')

    db = Database.get(match)
    if db is None: 
      # If the database does not exist, we respond with a DCube 404 message.
      return self.message_out(404, 'Database \\"%s\\" could not be found.'% match)

    try:
      creds = authenticate(credentials)
    except AuthenticationError:
      # If the user does not exist, we just return the name of this database to
      # indicate that it does indeed exist.
      return self.body_out('{"name":"%s"}'% db.name)
    except Authenticate, auth:
      # If the user did not authenticate, we send back the authentication prompt
      # along with some limited info about this database.
      return self.out(creds=auth.credentials,
          body={'name': db.name})

    user = BaseUser.get(creds[0])
    if user.username in db.owner_acl or user.username in db.manager_acl:
      # If the user is in the owner or manager ACL for this database, we send
      # them the whole shabang.
      return self.out(
          creds=creds,
          body={'name':db.name,
            'owner_acl':db.owner_acl,
            'manager_acl':db.manager_acl,
            'user_acl':db.user_acl})

    # Otherwise, we only send back the name of this db along with their
    # credentials.
    self.out(
        creds=creds,
        body={'name':db.name})

  def d3_put(self, request, credentials, match):
    # A call to the "/databases/" URL without a database path name is pointless.
    if not match: # match could be ''
      return self.message_out(501,
          'The URL \\"/databases/\\" is not implemented on this host.')

    creds = authenticate(credentials)
    user = BaseUser.get(creds[0])
    db = Database.get(match)
    if db is None: 
      # If the database does not exist, we have to assume that the caller
      # intended to create a new one by calling the DCube "put" method on this
      # URL. So, we need to make sure the caller is a member of the 'database'
      # permission level group.
      if 'database' not in user.groups:
        return self.authenticate_out(403,
            'User is forbidden to create or modify a database.', *creds)

      # Create the new database type object.
      db = Database(match)
      db.owner_acl = [user.username]
      db.put()

      # include it in the DCube response body along with the caller's
      # credentials.
      return self.out(201, 'Created.',
          creds=creds,
          body={
            'name': db.name,
            'owner_acl': db.owner_acl,
            'manager_acl': db.manager_acl,
            'user_acl': db.user_acl})

    # If we made it this far, that means the database exists and the caller
    # intends to modify it. But, before we get started we need to make sure the
    # caller sent us a dictionary of attributes for the database.
    if not isinstance(request, dict):
      return self.authenticate_out(400,
          'Invalid DCube message body to update database: (%s)'% \
              simplejson.dumps(request), *creds)
    
    # Next, we check to see if the caller is trying to modify the owner ACL.
    new_owner_acl = request.get('owner_acl')
    if isinstance(new_owner_acl, list) and new_owner_acl != db.owner_acl:
      # A user must be a member of the "account_admin" permission level group to
      # modify the owner ACL.
      if 'account_admin' not in user.groups:
        return self.authenticate_out(403,
            'User is forbidden to modify the owner access list of a database.',
            *creds)

      db.owner_acl = new_owner_acl

    # Next, we check to see if the caller is trying to modify the manager ACL.
    new_manager_acl = request.get('manager_acl')
    if isinstance(new_manager_acl, list) and new_manager_acl != db.manager_acl:
      # A user must be on the owner ACL or a member of the "account_admin"
      # permission level group to be able to modify the manager ACL.
      if user.username in db.owner_acl or 'account_admin' in user.groups:
        db.manager_acl = new_manager_acl

      else:
        return self.authenticate_out(403,
            'User is forbidden to modify the manager access list of this database.',
            *creds)

    # Last, we check to see if the user is trying to modify the user ACL.
    new_user_acl = request.get('user_acl') or []
    if isinstance(new_user_acl, list) and new_user_acl != db.user_acl:
      # The user must be on the owner ACL or the manager ACL, or a member of the
      # "account_admin" permission level group to be able to modify the user ACL.
      if user.username in db.owner_acl or \
          user.username in db.manager_acl or \
          'account_admin' in user.groups:
        db.user_acl = new_user_acl

      else:
        return self.authenticate_out(403,
            'User is forbidden to modify the user access list of this database.',
            *creds)

    # Put the changes to disk and return the new database representation to the
    # caller.
    db.put()
    self.out(200, 'Updated.',
        creds=creds,
        body={
          'name': db.name,
          'owner_acl': db.owner_acl,
          'manager_acl': db.manager_acl,
          'user_acl': db.user_acl})

  def d3_delete(self, request, credentials, match):
    # A call to the "/databases/" URL without a database path name is pointless.
    if not match: # match could be ''
      return self.message_out(501,
          'The URL \\"/databases/\\" is not implemented on this host.')

    db = Database.get(match)
    if db is None:
      # If it does not exist, this call gets a DCube 404 response.
      return self.message_out(404,
          'Database \\"%s\\" could not be found.'% match)

    creds = authenticate(credentials)
    user = BaseUser.get(creds[0])

    # A user must be a sys_admin to delete a database.
    if 'sys_admin' not in user.groups:
      return self.authenticate_out(403,
          'User forbidden to remove a database.', *creds)

    # Deleting a database is kind of a big deal, so we log it as such.
    logging.critical('Removing database "%s".', db.name)
    db.delete()
    self.message_out(204, 'Deleted database \\"%s\\".'% db.name)

class RootHandler(JsonRequestHandler):
  """Handle requests to the root "/" URL."""
  dcube_methods = ['get']

  def d3_get(self, request, credentials):
    creds = authenticate(credentials)
    self.out(creds=creds, body='DCube host on Google App Engine.')

class UsersHandler(JsonRequestHandler):
  """Handle DCube requests to a "/users/xyz" URL."""
  dcube_methods = ['get','put','delete']

  def d3_get(self, request, credentials, match):
    # A call to the "/users/" URL without a username is pointless.
    if not match: # match could be ''
      return self.message_out(501,
          'The URL \\"/users/\\" is not implemented on this host.')

    target_user = BaseUser.get(match)
    if target_user is None:
      # If the user does not exist, we send back a DCube 404 response.
      return self.message_out(404,
          'User \\"%s\\" could not be found.'% match)

    try:
      creds = authenticate(credentials)
    except AuthenticationError:
      # If the authenticated user does not exist, we send back a response with
      # limited data about the target user.
      return self.body_out('{"username":"%s"}'% target_user.username)
    except Authenticate, auth:
      # If the authenticated user did not authenticate we send back a response
      # prompting for the required credentials along with limited data about this
      # user.
      return self.out(creds=auth.credentials,
          body={'username': target_user.username})

    auth_user = BaseUser.get(creds[0])
    if auth_user.username == target_user.username or \
        'user_admin' in auth_user.groups:
      # The user is requesting their own data or the authenticated user is a
      # member of the 'user_admin' group, so we give it all to them.
      return self.out(creds=creds,
          body={'username': target_user.username, 'groups': target_user.groups})

    # Limited response for users with restricted permissions.
    self.out(creds=creds,
        body={'username': target_user.username})

  def d3_put(self, request, credentials, match):
    # A call to the "/users/" URL without a username is pointless.
    if not match: # match could be ''
      self.message_out(501,
          'The URL \\"/users/\\" is not implemented on this host.')
      return

    target_user = BaseUser.get(match)
    if target_user is None:
      # If the user does not exist, we assume the caller intended to create a new
      # one.
      target_user = BaseUser(match)
      new_user = pychap.authenticate(store.put_user, target_user)
      return self.out(status=201, message='Created.',
          creds=new_user.credentials,
          body={'username': new_user.username})

    # Otherwise we assume the caller is trying to update this user's data, so we
    # try to authenticate.
    creds = authenticate(credentials)
    auth_user = BaseUser.get(creds[0])

    # It is wrong to assume that we are existing in a magic pony land where all
    # the planets line up prefectly and our programs are bug free.  In this
    # case, if we don't make this seemingly meaningless assigment of one user
    # object to another, then when a user updates their own data, really bad
    # shit happens to our authentication scheme.
    if target_user.username == auth_user.username:
      target_user = auth_user

    # The first thing we need to do is check to see if the caller is trying to
    # update the permission level group membership.
    new_groups = request.get('groups')
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

    target_user.put()
    self.out(status=200, message='Updated.',
        creds=creds,
        body={'username': target_user.username, 'groups': target_user.groups})

  def d3_delete(self, request, credentials, match):
    # A call to the "/users/" URL without a username is pointless.
    if not match: # match could be ''
      self.message_out(501,
          'The URL \\"/users/\\" is not implemented on this host.')
      return

    target_user = BaseUser.get(match)
    if target_user is None:
    # If the user does not exist, we send back a DCube 404 response.
      return self.message_out(404, 'User \\"%s\\" could not be found.'% match)

    # Get the authenticated user.
    creds = authenticate(credentials)
    auth_user = BaseUser.get(creds[0])

    # We never alow a user to delete another user.
    if auth_user.username != target_user.username:
      return self.authenticate_out(403,
          'Deleting another user is forbidden.', *creds)

    auth_user.delete()
    self.message_out(204, 'Deleted user \\"%s\\".'% auth_user.username)

class RobotsHandler(BaseHandler):
  """Handle requests to the "/robots.txt" URL."""
  _allow = 'GET'
  def get(self):
    self.response.headers['content-type'] = 'text/plain'
    self.response.headers['cache-control'] = 'public'
    self.response.headers['last-modified'] = 'Fri, 1 Jan 2010 00:00:01 GMT'
    self.response.headers['allow'] = 'GET'
    # Expires in 8 weeks.
    self.response.headers['expires'] = formatdate(time.time() + (604800 * 8))
    self.response.out.write('User-agent: *\nDisallow: /')

class NotFoundHandler(webapp.RequestHandler):
  """Handle requests to any URL that is not implemented."""
  def error(self, code):
    self.response.set_status(404)
    self.response.headers['cache-control'] = 'public'
    # Expires in 8 weeks.
    self.response.headers['expires'] = formatdate(time.time() + (604800 * 8))

application = webapp.WSGIApplication([
  # Database management "/databases/xyz" urls.
  ('/databases/(\w*)', DatabasesHandler),

  # Root "/" domain url
  ('/', RootHandler),

  # User management "/users/xyz" urls.
  ('/users/(\w*)', UsersHandler), 

  # Web crawling robots take notice:
  ('/robots\.txt', RobotsHandler),

  # Not Found
  ('.*', NotFoundHandler)])

def main():
  util.run_wsgi_app(application)

# If this is indeed the main process, call the main() function that was just
# defined.
if __name__ == '__main__':
  main()
