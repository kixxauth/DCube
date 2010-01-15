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
import session
import logging

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
  this.authenticate = []
  if this.userExists:
    storeFactory('delete_user')()
    logging.info('Deleted user "%s"', this.username)
  this.message = 'deleted user "%s"' % this.username

def base_handler(this, storeFactory):
  """Base handler for all calls to '/' root domain url.
  """
  this.message = 'DCube: Distributed Discriptive Datastore JSONRequest server.'

def main():
  # see the docs for session.start() for more about the url map list.
  session.start([

    ('/users/(\w*)',
      {'PUT': ([users_base_handler, users_put_handler], True),
       'GET': ([users_base_handler, users_get_handler], True),
       'DELETE': ([users_base_handler, users_delete_handler], True)}),

    ('/',
      {'GET': ([base_handler], True)})

    ])

if __name__ == '__main__':
  main()
