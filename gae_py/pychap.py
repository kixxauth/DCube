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

class ChapUser():
  """Class definition for the object passed to the putuser callback function
  given to authenticate(). See the authenticate() docs for more info.
  """
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
  """Utility used to create unique, un-guessable strings."""
  k = str(datetime.datetime.utcnow()) + username
  s = str(random.randint(0, 9999))
  return hmac.new(k.encode('ascii'), s.encode('ascii'), hashlib.sha1).hexdigest()

def authenticate(putuser,
                 username=None,
                 passkey=None,
                 nonce=None,
                 nextnonce=None,
                 cnonce=None,
                 response=None):
  """Authenticates a user with the given credentials.

  Args:

    putuser - A function that will be invoked and passed a ChapUser instance
      when authenticate has reached a point in the protocol where user data
      needs to be persisted.  Callers of authenticate() should use this
      function to persist the attributes given on the ChapUser instance in any
      way they see fit.

    username - The user name string.
    passkey - The last known passkey string.
    nonce - The last known nonce string.
    nextnonce - The last known nextnonce string.
    cnonce - The cnonce string sent by the client.
    response - The response string sent by the client.

  Returns:
    A ChapUser instance with the message attribute set to one of USER_NA,
    MISSING_CREDS, SETTING_PASSKEY, UNMODIFIED, DENIED, or OK.

  If putuser is not callable or username is not a basestring an assertion error
  is raised.

  If nonce or nextnonce are None it is assumed that a new user is being created
  and the ChapUser instance will be given the new nonce and nextnonce
  attributes, the message attribute will be set to USER_NA, and the
  authenticated attribute will be set to False. The putuser function will be
  called before authenticate() returns.

  If nonce and nextnonce are set, but cnonce and nonce were not supplied by the
  client the message attribute of the ChapUser instance is set to MISSING_CREDS
  and the authenticated attribute is set to False.

  If nonce and nextnonce are set, but passkey is not set, it is assumed that
  the passkey is being set for this user the first time, or the passkey for
  this user needs to be reset because of a lost, breached, or forgotten
  password. In this case the passkey attribute of the ChapUser instance will be
  set, the message attribute will be set to SETTING_PASSKEY, and the
  autheticated attribute will be set to True. The nonce and nextnonce
  attributes will also be updated. The putuser function will also be invoked
  with the updated ChapUser instance.

  If the client failed to use a user given passkey to create the response and
  cnonce from the nonce and nextnonce the authenticated attribute of the
  ChapUser instance is set to False and message attribute is set to UNMODIFIED.

  If the response cannot be matched to the passkey the user is denied and the
  authenticated attribute of the ChapUser instance is set to False and message
  attribute is set to DENIED.

  If the response is matched to the passkey the user is authenticated. The
  nonce, nextnonce, and passkey attributes of the ChapUser instance are all
  updated. The authenticated attribute is set to True and the message attribute
  is set to OK.  The putuser function is also invoked and passed the updated
  ChapUser instance.
   
  """

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
