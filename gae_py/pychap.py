"""PyChap is a server side Python implementation of a challenge response
authentication protocol used to authenticate users over a network.  It does not
require the storage of plain text passwords, and the stored password
equivalents are changed at the start of every session, or on every request over
the network, depending on the usage of this module.

The functionality of PyChap is just some very simple logic code that may be included
in your project or simply used to better understand the alternative challenge
response protocol system.
"""

import hashlib
import hmac
import datetime
import random

USER_NA         = 'user does not exist'
MISSING_CREDS   = 'proper cnonce or response was not supplied'
SETTING_PASSKEY = 'setting or resetting the user passkey'
UNMODIFIED      = 'the cnonce or response were not modified by the client'
DENIED          = 'the supplied passkey response did not authenticate'
OK              = 'authenticated ok'

def createNonce(username):
  """Utility used to create unique, un-guessable strings."""
  k = str(datetime.datetime.utcnow()) + username
  s = str(random.randint(0, 9999))
  return hmac.new(k.encode('ascii'), s.encode('ascii'), hashlib.sha1).hexdigest()

def authenticate(putuser, user):
  """Authenticates a user with the given credentials.

  Args:

    putuser - A function that will be invoked and passed a ChapUser instance
      when authenticate has reached a point in the protocol where user data
      needs to be persisted.  Callers of authenticate() should use this
      function to persist the attributes given on the ChapUser instance in any
      way they see fit.

    user - An instance object with the following attributes:
      username - The user name string.
      passkey - The last known passkey string.
      nonce - The last known nonce string.
      nextnonce - The last known nextnonce string.
      cnonce - The cnonce string sent by the client.
      response - The response string sent by the client.

  Returns:
    The passed in user instance object with the 'message' attribute set to one
    of USER_NA, MISSING_CREDS, SETTING_PASSKEY, UNMODIFIED, DENIED, OK and the
    'authenticated' attribute set to True or False.

  If putuser is not callable or user.username is not a basestring an assertion
  error is raised.

  If user.nonce or user.nextnonce are None it is assumed that a new user is
  being created and the returned instance will be given the new nonce and
  nextnonce attributes, the message attribute will be set to USER_NA, and the
  authenticated attribute will be set to False. The putuser function will be
  called before authenticate() returns.

  If user.nonce and user.nextnonce are set, but user.cnonce and user.nonce were
  not supplied by the client the message attribute of the returned instance is
  set to MISSING_CREDS and the authenticated attribute is set to False.

  If user.nonce and user.nextnonce are set, but user.passkey is not set, it is
  assumed that the passkey is being set for this user the first time, or the
  passkey for this user needs to be reset because of a lost, breached, or
  forgotten password. In this case the passkey attribute of the returned
  instance will be set, the message attribute will be set to SETTING_PASSKEY,
  and the autheticated attribute will be set to True. The nonce and nextnonce
  attributes will also be updated. The putuser function will be invoked with
  the updated instance.

  If the client failed to use a user given passkey to create the response and
  cnonce from the nonce and nextnonce the authenticated attribute of the
  returned instance is set to False and message attribute is set to UNMODIFIED.

  If user.response cannot be matched to user.passkey the user is denied and the
  authenticated attribute of the returned instance is set to False and message
  attribute is set to DENIED.

  If user.response is matched to user.passkey the user is authenticated. The
  nonce, nextnonce, and passkey attributes of the returned instance are all
  updated. The authenticated attribute is set to True and the message attribute
  is set to OK.  The putuser function is also invoked and passed the updated
  instance.
   
  """

  assert callable(putuser), \
      'first argument to pychap.authenticate() must be a function'

  assert isinstance(getattr(user, 'username', False), basestring), \
      'user.username passed to pychap.authenticate() must be a string.'

  user.nonce = getattr(user, 'nonce', False) or None
  assert (isinstance(user.nonce, basestring) or user.nonce is None), \
      'user.nonce passed to pychap.authenticate() must be a string or None'
  user.nextnonce = getattr(user, 'nextnonce', False) or None
  assert (isinstance(user.nextnonce, basestring) or user.nextnonce is None), \
      'nextnonce passed to pychap.authenticate() must be a string or None'


  # new user
  if user.nonce is None or user.nextnonce is None:
    user.nonce = createNonce(user.username)
    user.nextnonce = createNonce(user.username)
    user.message = USER_NA
    user.authenticated = False
    putuser(user)
    return user 

  # no credentials supplied by the client
  user.cnonce = getattr(user, 'cnonce', False) or None
  user.response = getattr(user, 'response', False) or None
  assert (isinstance(user.cnonce, basestring) or user.cnonce is None), \
      'user.cnonce passed to pychap.authenticate() must be a string or None'
  assert (isinstance(user.response, basestring) or user.response is None), \
      'user.response passed to pychap.authenticate() must be a string or None'
  if user.cnonce is None or user.response is None:
    user.message = MISSING_CREDS 
    user.authenticated = False
    return user

  # no stored passkey: setting or re-setting the passkey
  user.passkey = getattr(user, 'passkey', False) or None
  assert (isinstance(user.passkey, basestring) or user.passkey is None), \
      'user.passkey passed to pychap.authenticate() must be a string or None'
  if user.passkey is None:
    user.passkey = user.cnonce
    user.nonce = user.nextnonce
    user.nextnonce = createNonce(user.username)
    user.authenticated = True
    user.message = SETTING_PASSKEY
    putuser(user)
    return user

  # Now that we know we have a passkey, nonce, and nextnonce for the user we
  # have to make sure that the client has at least modified nonce and nextnonce
  # into response and cnonce with user's passkey.
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
  user.passkey = user.cnonce
  user.nonce = user.nextnonce
  user.nextnonce = createNonce(user.username)
  user.authenticated = True
  user.message = OK
  putuser(user)
  return user
