"""This module contains the models and utility functions for working with the
App Engine datastore.
"""
import logging

from google.appengine.ext import db
from google.appengine.api import datastore
from google.appengine.api import datastore_errors

class BaseUser(db.Model):
  __prefix = 'BaseUser:'
  passkey = db.StringProperty(indexed=False)
  nonce = db.StringProperty(indexed=False)
  nextnonce = db.StringProperty(indexed=False)
  groups = db.StringListProperty(default=['users'])

  def __init__(self, username=None, _from_entity=False, **kwds):
    if username is not None:
      assert _from_entity is False
      self.username = username
      db.Model.__init__(self, key_name=self.__prefix + str(username))
    else:
      assert _from_entity
      db.Model.__init__(self, _from_entity=True, **kwds)

  def __repr__(self):
    return '{username:%s, passkey:%s, nonce:%s, nextnonce:%s, groups:%s}'% \
        (self.username, self.passkey, self.nonce, self.nextnonce, self.groups)

  @classmethod
  def get(cls, name):
    try:
      entity = datastore.Get(datastore.Key.from_path(
          cls.__name__, cls.__prefix + str(name)))
    except datastore_errors.EntityNotFoundError:
      return None
    user = cls.from_entity(entity)
    user.username = name
    return user

  def put(self):
    put_user(self)

  @property
  def credentials(self):
    return [self.username, self.nonce, self.nextnonce]

class Database(db.Model):
  __prefix = 'Database:'
  owner_acl = db.StringListProperty()
  manager_acl = db.StringListProperty()
  user_acl = db.StringListProperty()

  def __init__(self, dbname=None, _from_entity=False, **kwds):
    if dbname is not None:
      assert _from_entity is False
      self.name = dbname
      db.Model.__init__(self, key_name=self.__prefix + str(dbname))
    else:
      assert _from_entity
      db.Model.__init__(self, _from_entity=True, **kwds)

  @classmethod
  def get(cls, name):
    try:
      entity = datastore.Get(datastore.Key.from_path(
          cls.__name__, cls.__prefix + str(name)))
    except datastore_errors.EntityNotFoundError:
      return None
    db = cls.from_entity(entity)
    db.name = name
    return db

class GeneralData(db.Expando):
  __prefix = 'GeneralData:'
  text_body = db.TextProperty()

  def __init__(self, keys=None, _from_entity=False, **kwds):
    if keys is not None:
      assert _from_entity is False
      dbname, key = keys
      db.Expando.__init__(self, key_name=self.__prefix + str(dbname) + str(key))
    else:
      assert _from_entity
      db.Expando.__init__(self, _from_entity=True, **kwds)

  @classmethod
  def get(cls, keys):
    dbname, key = keys
    try:
      entity = datastore.Get(datastore.Key.from_path(
          cls.__name__, cls.__prefix + str(dbname) + str(key)))
    except datastore_errors.EntityNotFoundError:
      return None
    return cls.from_entity(entity)

  def key_name(self, dbname):
    r = self.__prefix + str(dbname)
    return self.key().name().replace(r, '', 1)

def put(model):
  assert not isinstance(model, BaseUser)
  db.put(model)

def put_user(user):
  assert isinstance(user, BaseUser)
  assert isinstance(user.nonce, basestring)
  assert isinstance(user.nextnonce, basestring)
  db.put(user)

