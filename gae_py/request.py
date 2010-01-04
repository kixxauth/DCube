import session
import logging

def users_base_handler(this, storeFactory, user_url):
  if len(user_url) is 0:
    this.status = 403
    this.message = 'access to url "/users/" is forbidden'
    return False

  if user_url != this.username:
    this.status = 400
    this.message = 'username "%s" does not match url "%s"' % \
        (this.username, this.url)
    return False

  return True

def users_put_handler(this, storeFactory, user_url):
  if not this.userExists:
    nonce, nextnonce = storeFactory('create_new_user')()
    logging.info('Created new user "%s"', this.username)
    this.status = 201
    this.message = 'created new user "%s"' % this.username
    this.authenticate = [this.username, nonce, nextnonce]

  this.body = storeFactory('get_public_user')()

def users_get_handler(this, storeFactory, user_url):
  if this.userExists:
    this.body = storeFactory('get_public_user')()
  else:
    this.status = 404
    this.message = 'user "%s" not found' % this.username
    this.authenticate = []

def users_delete_handler(this, storeFactory, user_url):
  this.authenticate = []
  if this.userExists:
    storeFactory('delete_user')()
    logging.info('Deleted user "%s"', this.username)
  this.message = 'deleted user "%s"' % this.username

def base_handler(this, storeFactory):
  this.message = 'DCube: Distributed Discriptive Datastore JSONRequest server.'

def main():
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
