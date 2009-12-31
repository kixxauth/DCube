import hashlib
import hmac
import datetime
import random

USER_NA         = 'user does not exist'
MISSING_CREDS   = 'proper cnonce or response was not supplied'
SETTING_PASSKEY = 'setting or resetting the user passkey'
UNMODIFIED      = 'the cnonce or response were not modified'
DENIED          = 'the supplied passkey response did not authenticate'
OK              = 'authenticated ok'

class ChapUser():
  def __init__(self,
               username=None,
               passkey=None,
               nonce=None,
               nextnonce=None,
               cnonce=None,
               response=None):
    self.username = username
    self.passkey = passkey
    self.nonce = nonce
    self.nextnonce = nextnonce
    self.cnonce = cnonce
    self.response = response

def createNonce(username):
  return hmac.new(
      str(datetime.datetime.utcnow()) + username,
      str(random.randint(0, 9999)),
      hashlib.sha1).hexdigest()

def authenticate(putuser,
                 username=None,
                 passkey=None,
                 nonce=None,
                 nextnonce=None,
                 cnonce=None,
                 response=None):

  assert callable(putuser), \
      'first argument to pychap.authenticate() must be a function'

  assert isinstance(username, basestring), \
      'username passed to pychap.authenticate() must be a string.'

  assert (isinstance(nonce, basestring) or nonce is None), \
      'nonce passed to pychap.authenticate() must be a string or None'

  assert (isinstance(nextnonce, basestring) or nextnonce is None), \
      'nextnonce passed to pychap.authenticate() must be a string or None'

  assert (isinstance(cnonce, basestring) or cnonce is None), \
      'cnonce passed to pychap.authenticate() must be a string or None'

  assert (isinstance(response, basestring) or response is None), \
      'response passed to pychap.authenticate() must be a string or None'

  user = ChapUser(username=username,
                  passkey=passkey,
                  nonce=nonce,
                  nextnonce=nextnonce,
                  cnonce=cnonce,
                  response=response)

  # new user
  if user.nonce is None or user.nextnonce is None:
    user.nonce = createNonce(username)
    user.nextnonce = createNonce(username)
    user.message = USER_NA
    user.authenticated = False
    putuser(user)
    return user 

  # no credentials supplied by the client
  if user.cnonce is None or user.response is None:
    user.message = MISSING_CREDS 
    user.authenticated = False
    return user

  # no stored passkey: setting or re-setting the passkey
  if user.passkey is None:
    user.passkey = cnonce
    user.nonce = nextnonce
    user.nextnonce = createNonce(user.username)
    user.authenticated = True
    user.message = SETTING_PASSKEY
    putuser(user)
    return user

  # Now that we know we have a passkey, nonce, and nextnonce for the user we
  # have to make sure that the client has at least modified nonce and nextnonce
  # into response and cnonce with user's passkey.
  assert isinstance(user.nonce, basestring), \
      'user["nonce"] passed to pychap.authenticate() should be a string.'

  assert isinstance(user.nextnonce, basestring), \
      'user["nextnonce"] passed to pychap.authenticate() should be a string.'

  if user.cnonce == hashlib.sha1(
      hashlib.sha1(user.nextnonce).hexdigest()).hexdigest() \
          or user.response == hashlib.sha1(user.nonce).hexdigest():
    user.authenticated = False
    user.message = UNMODIFIED
    return user

  # authenticate
  assert isinstance(user.passkey, basestring), \
      'user.passkey passed to pychap.authenticate() should be a string.'
  if hashlib.sha1(user.response).hexdigest() != user.passkey:
    user.authenticated = False
    user.message = DENIED
    return user

  # user is ok
  user.passkey = cnonce
  user.nonce = nextnonce
  user.nextnonce = createNonce(user.username)
  user.authenticated = True
  user.message = OK
  putuser(user)
  return user
