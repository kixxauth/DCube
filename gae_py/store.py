"""This module contains the models and utility functions for working with the
App Engine datastore.
 
One of the design goals of our program is to provide limited access to data in
the datastore based on a "Unix like" permissions system of users and user
groups. The foundation for this design is to limit the possibility of
programmer errors that could result in exposing more of the datastore than what
is intended.

Encapsulating this module is part of implementing that design goal.

This module should only ever be imported into the 'factory' module
(factory.py). That module provides the factory functions for properly working
with the datastore, and the api of this module should not be directly accessed
in any other way.
"""
from google.appengine.ext import db

import logging

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

# todo: this should hit memcached first
def getBaseUser(username):
  user = BaseUser.get_by_key_name('username:%s' % username) or \
      BaseUserPrototype()
  return user

def putBaseUser(*a, **k):
  ent = BaseUser.get_by_key_name('username:%s' % k['username']) or \
      BaseUser(key_name=('username:%s' % k['username']))

  if not k.get('nonce') is None:
    ent.nonce = k['nonce']

  if not k.get('nextnonce') is None:
    ent.nextnonce = k['nextnonce']

  if not k.get('passkey') is None:
    ent.passkey = k['passkey']

  if not k.get('groups') is None:
    ent.groups = k['groups']

  ent.put()
  return ({'username': k['username'],
      'groups': ent.groups}, ent.nonce, ent.nextnonce)

def deleteBaseUser(username):
  user = BaseUser.get_by_key_name('username:%s' % username)
  if not user is None:
    user.delete()
