import store
import pychap

import logging

def get_chap_user_creds(username, groups):
  def getChapUserCreds():
    user = store.getBaseUser(username)
    return dict(username=username,
            nonce=user.nonce,
            nextnonce=user.nextnonce,
            passkey=user.passkey)
  return getChapUserCreds

def update_chap_user_creds(username, groups):
  def updateChapUserCreds(user):
    assert user.username == username, \
        'factory:: Invalid username in update_chap_user_creds().'
    u = store.getBaseUser(username)
    # make sure the user exists before we put the updates to disk
    if (u.nonce and u.nextnonce):
      store.putBaseUser(**user.__dict__)
  return updateChapUserCreds

def get_user_groups(username, groups):
  def getUserGroups():
    return store.getBaseUser(username).groups
  return getUserGroups

def create_new_user(username, groups):
  def createNewUser():
    def put_new_user(u):
      assert u.username == username, \
          'factory:: Invalid username in update_chap_user_creds().'
      store.putBaseUser(**u.__dict__)

    user = pychap.authenticate(put_new_user, username)
    return [user.nonce, user.nextnonce]

  return createNewUser

def delete_user(username, groups):
  def deleteUser():
    store.deleteBaseUser(username)
  return deleteUser
