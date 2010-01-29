"""This module contains the models and utility functions for working with the
App Engine datastore.
"""
from google.appengine.ext import db
from google.appengine.api import datastore
from google.appengine.api import datastore_errors

import logging

def get(keys):
  multiple = isinstance(keys, list) or isinstance(keys, tuple)
  try:
    entities = datastore.Get(keys)
  except datastore_errors.EntityNotFoundError:
    assert not multiple
    return None

  return entities

class BaseUser(object):
  kind = 'BaseUser'
  prefix = 'BaseUser:%s'

class Database(object):
  kind = 'Database'
  prefix = 'Database:%s'

def get_baseuser(username):
  ent = get(datastore.Key.from_path(
    BaseUser.kind, BaseUser.prefix % username)) 

  if ent is None:
    return None

  user = BaseUser()
  user.username = username
  user.passkey = ent.get('passkey')
  user.nonce = ent.get('nonce')
  user.nextnonce = ent.get('nextnonce')
  user.groups = ent.get('groups')
  return user

def put_baseuser(user):
  ent = datastore.Entity(BaseUser.kind, name=BaseUser.prefix % user.username)
  for k in ['nonce', 'nextnonce', 'passkey', 'groups']:
    try:
      ent[k] = getattr(user, k)
    except AttributeError:
      user.__dict__[k] = None
  datastore.Put(ent)
  return user

def delete_baseuser(username):
  datastore.Delete(datastore.Key.from_path(
    BaseUser.kind, BaseUser.prefix % username))

def get_database(dbname):
  ent = get(datastore.Key.from_path(
    Database.kind, Database.prefix % dbname)) 

  if ent is None:
    return None

  db = Database()
  db.name = dbname
  db.owner_acl = ent.get('owner_acl')
  db.manager_acl = ent.get('manager_acl')
  db.user_acl = ent.get('user_acl')
  return db

def put_database(db):
  ent = datastore.Entity(Database.kind, name=Database.prefix % db.name)
  for k in ['owner_acl', 'manager_acl', 'user_acl']:
    try:
      ent[k] = getattr(db, k)
    except AttributeError:
      db.__dict__[k] = None
  datastore.Put(ent)
  return db

def delete_database(dbname):
  datastore.Delete(datastore.Key.from_path(
    Database.kind, Database.prefix % dbname))
