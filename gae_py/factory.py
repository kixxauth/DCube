import store
import pychap

class Prototype():
  pass

def get_chap_user_creds(username):
  user = store.getBaseUser(username)
  rv = Prototype()
  rv.exists = user.exists
  rv.nonce = user.nonce
  rv.nextnonce = user.nextnonce
  rv.passkey = user.passkey
  return rv

def get_user_groups(username):
  return store.getBaseUser(username).groups

def create_new_user(username):
  assert not store.getBaseUser(username).exists, \
      'Cannot create existing user "%s".' % username

  user = pychap.authenticate(
      lambda u: store.putBaseUser(**u.__dict__),
      username)
  return [user.nonce, user.nextnonce]
