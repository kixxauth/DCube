"""A collection of functions called by get_builder() in gate.py. Each of the
functions in this module is a builder that returns another function. The
returned functions expose restricted datastore capabilities.

Each function takes a username and a list of groups the user is a member of
and returns a function that will provide access to a restricted datastore
capability based on the given username and group membership list.
"""
import store
import pychap
import groups

import logging

GROUPS = groups.map

def get_db(username, level):
  def getdb(db_name):
    db = store.get_db(db_name)
    if db is None:
      return None

    # Check the access lists before we allow this user to access it.
    if not username in db.owner_acl:
      assert username in db.manager_acl, 'NOT MANAGER'

  return getdb


def delete_db(username, level):
  def deletedb(db_name):
    db = store.get_db(db_name)
    if db is None:
      return

    # Check the db owner access list before we allow this user to delete it.
    assert username in db.owner_acl, 'NOT OWNER'
    store.remove_db(db_name)

  return deletedb

def get_chap_user_creds(username, level):
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

def update_chap_user_creds(username, level):
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

# todo: this should check the username == 'ROOT'
def get_user_groups(username, level):
  """Returns a function that will return the group membership list for the
  given username.
  """
  def getUserGroups():
    return store.getBaseUser(username).groups
  return getUserGroups

def create_new_user(username, level):
  """Returns a function that allows its caller to create a new user entity in
  the datastore.
  """
  # todo: A sanity check should be made here to be sure that this user does not
  # already exist
  def createNewUser():
    return store.putBaseUser(
        **pychap.authenticate(lambda x:1, username).__dict__)

  return createNewUser

def get_public_user(loggedin_username, level):
  """Returns a function that will return the "public" attribes of the given
  user in the form of a dictionary.
  """
  def getPublicUser(username):
    user = store.getBaseUser(username)
    if user.nonce is None:
      return None # user does not exist yet
    if loggedin_username == username:
      return {'username': username, 'groups': user.groups}
    if level >= GROUPS['account_admin']['level']:
      return {'username': username, 'groups': user.groups}
    return {'username': username}

  return getPublicUser

# todo: This needs to return something more useful than False.
def update_public_user(loggedin_username, level):
  """Returns a function that allows the caller to update a user provided the
  permission level requirements are met.
  """
  def updatePublicUser(user):
    stored_user = store.getBaseUser(user['username'])

    stored_user.level = 0
    for g in stored_user.groups:
      if stored_user.level < GROUPS[g]['level']:
        stored_user.level = GROUPS[g]['level']

    groups = user['groups']
    if groups != stored_user.groups:
      # request to change groups
      # can the logged in user make this change?
      if loggedin_username != user['username'] and \
          (level < stored_user.level or level < GROUPS['account_admin']['level']):
        return False

      # can the logged in user update these groups?
      for g in groups:
        if GROUPS.get(g) is None:
          return False
        if not g in stored_user.groups and \
            not level > GROUPS[g]['level']:
              return False

    return store.putBaseUser(username=user['username'], groups=groups)

  return updatePublicUser

def delete_user(username, level):
  def deleteUser():
    store.deleteBaseUser(username)
  return deleteUser

