"""A collection of functions called by get_builder() in gate.py. Each of the
functions in this module is a builder that returns another function. The
returned functions expose restricted datastore capabilities.

Each function takes a username and a list of groups the user is a member of
and returns a function that will provide access to a restricted datastore
capability based on the given username and group membership list.
"""
import store
import pychap

import logging

def get_chap_user_creds(username, groups):
  """Returns a function that will return authentication attributes for the
  given user.
  """
  def getChapUserCreds():
    user = store.getBaseUser(username)
    return dict(username=username,
            nonce=user.nonce,
            nextnonce=user.nextnonce,
            passkey=user.passkey)
  return getChapUserCreds

def update_chap_user_creds(username, groups):
  """Returns a function that will allow its caller to update authentication
  attributes for a user in the datastore.
  """
  def updateChapUserCreds(user):
    assert user.username == username, \
        'factory:: Invalid username in update_chap_user_creds().'
    u = store.getBaseUser(username)
    # make sure the user exists before we put the updates to disk
    if (u.nonce and u.nextnonce):
      store.putBaseUser(**user.__dict__)
  return updateChapUserCreds

def get_user_groups(username, groups):
  """Returns a function that will return the group membership list for the
  given username.
  """
  def getUserGroups():
    return store.getBaseUser(username).groups
  return getUserGroups

def create_new_user(username, groups):
  """Returns a function that allows its caller to create a new user entity in
  the datastore.
  """
  def createNewUser():
    def put_new_user(u):
      assert u.username == username, \
          'factory:: Invalid username in update_chap_user_creds().'
      store.putBaseUser(**u.__dict__)

    user = pychap.authenticate(put_new_user, username)
    return [user.nonce, user.nextnonce]

  return createNewUser

def get_public_user(username, groups):
  """Returns a function that will return the "public" attribes of the given
  user in the form of a dictionary.
  """
  def getPublicUser():
    user = store.getBaseUser(username)
    if user.nonce is None:
      return None # user does not exist yet
    return {'username': username, 'groups': user.groups}
  return getPublicUser

def delete_user(username, groups):
  def deleteUser():
    store.deleteBaseUser(username)
  return deleteUser
