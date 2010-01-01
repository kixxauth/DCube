from google.appengine.ext import db

class BaseUserPrototype():
  def __init__(self):
    self.nonce = None
    self.nextnonce = None
    self.passkey = None
    self.groups= ['users']

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

  # The permission groups the user belongs to. All users belong to the 'users'
  # level 0 group by defualt
  groups = db.StringListProperty(default=['users'])

def getBaseUser(username):
  user = BaseUser.get_by_key_name('username:%s' % username) or \
      BaseUserPrototype()
  user.exists = isinstance(user, BaseUser)
  return user

def putBaseUser(*a, **k):
  ent = BaseUser.get_by_key_name('username:%s' % k['username']) or \
      BaseUser(key_name=('username:%s' % k['username']))
  ent.nonce = k.get('nonce') or ent.nonce
  ent.nextnonce = k.get('nextnonce') or ent.nextnonce
  ent.passkey = k.get('passkey') or ent.passkey
  ent.groups = k.get('groups') or ent.groups
  ent.put()
