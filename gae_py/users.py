import session

def users_put_handler(this, storeFactory, user_url):
  if len(user_url) is 0:
    this.status = 403
    this.message = 'access to url "/users/" is forbidden'
    return

  if user_url != this.username:
    this.status = 400
    this.message = 'username "%s" does not match url "%s"' % \
        (this.username, this.url)
    return

  if not this.userExists:
    nonce, nextnonce = storeFactory('create_new_user')(this.username)
    this.status = 201
    this.message = 'created new user "%s"' % this.username
    this.authenticate = [this.username, nonce, nextnonce]
    return

def main():
  session.start([('/users/(\w*)', {'PUT': users_put_handler})])

if __name__ == '__main__':
  main()
