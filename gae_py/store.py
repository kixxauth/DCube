"""This module contains the models and utility functions for working with the
App Engine datastore.
"""
import logging

from google.appengine.ext import db
from google.appengine.api import datastore
from google.appengine.api import datastore_errors

class BaseUser(db.Model):
  """Derived datastore model class for user managment."""
  __prefix = 'BaseUser:'
  passkey = db.StringProperty(indexed=False)
  nonce = db.StringProperty(indexed=False)
  nextnonce = db.StringProperty(indexed=False)
  groups = db.StringListProperty(default=['users'])

  def __init__(self, username=None, _from_entity=False, **kwds):
    if username is not None:
      # If the username is given, we assume that the constructor has been
      # called from the handler routine and we create this model with the
      # correct "sanitized" key_name.
      assert _from_entity is False
      self.username = username
      db.Model.__init__(self, key_name=self.__prefix + str(username))
    else:
      # If the username is not given, we assume this constructor was called
      # from the GAE datastore code, and construct the object like expected.
      assert _from_entity
      db.Model.__init__(self, _from_entity=True, **kwds)

  def __repr__(self):
    return '{username:%s, passkey:%s, nonce:%s, nextnonce:%s, groups:%s}'% \
        (self.username, self.passkey, self.nonce, self.nextnonce, self.groups)

  @classmethod
  def get(cls, name):
    """Allows a caller to get an instance of this class using only the name."""
    try:
      entity = datastore.Get(datastore.Key.from_path(
          cls.__name__, cls.__prefix + str(name)))
    except datastore_errors.EntityNotFoundError:
      return None
    user = cls.from_entity(entity)
    user.username = name
    return user

  def put(self):
    """Redirect db.Model.put() through our own put_user().

    This trick allows us to do better sanity checks.
    
    """
    put_user(self)

  @property
  def credentials(self):
    return [self.username, self.nonce, self.nextnonce]

class Database(db.Model):
  """Derived datastore model class for database managment."""
  __prefix = 'Database:'
  owner_acl = db.StringListProperty()
  manager_acl = db.StringListProperty()
  user_acl = db.StringListProperty()

  def __init__(self, dbname=None, _from_entity=False, **kwds):
    if dbname is not None:
      # If the database name is given, we assume that the constructor has been
      # called from the handler routine and we create this model with the
      # correct "sanitized" key_name.
      assert _from_entity is False
      self.name = dbname
      db.Model.__init__(self, key_name=self.__prefix + str(dbname))
    else:
      # If the username is not given, we assume this constructor was called
      # from the GAE datastore code, and construct the object like expected.
      assert _from_entity
      db.Model.__init__(self, _from_entity=True, **kwds)

  @classmethod
  def get(cls, name):
    """Allows a caller to get an instance of this class using only the name."""
    try:
      entity = datastore.Get(datastore.Key.from_path(
          cls.__name__, cls.__prefix + str(name)))
    except datastore_errors.EntityNotFoundError:
      return None
    db = cls.from_entity(entity)
    db.name = name
    return db

class GeneralData(db.Expando):
  """Derived datastore model class for general data storage and query."""
  # TODO: Could we improve this program by making GeneralData instances children of
  # their parent Database instances? Useful for local transactions?
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
    """Get an instance of this class using only the datbase name and given key.

    Args:
      keys: A tuple. The first item in the tuple must be the name of the
      database, and the second item must be the key given from the query
      request.
    
    """
    dbname, key = keys
    try:
      entity = datastore.Get(datastore.Key.from_path(
          cls.__name__, cls.__prefix + str(dbname) + str(key)))
    except datastore_errors.EntityNotFoundError:
      return None
    return cls.from_entity(entity)

  def key_name(self, dbname):
    """Given the database name, return the key name of an instance."""
    # TODO: It should be possible to do this without the dbname.
    r = self.__prefix + str(dbname)
    return self.key().name().replace(r, '', 1)

def put_user(user):
  """Adds aditional sanity checks when saving a user entity to the datastore.

  """
  assert isinstance(user, BaseUser)
  assert isinstance(user.nonce, basestring)
  assert isinstance(user.nextnonce, basestring)
  db.put(user)

