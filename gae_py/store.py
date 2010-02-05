"""This module contains the models and utility functions for working with the
App Engine datastore.
"""
from google.appengine.ext import db
from google.appengine.api import datastore
from google.appengine.api import datastore_errors

import logging

class Model(object):
  """## The base data Model class. ##

  Attrs:
    key: The normalized datastore key_name for this entity instance.
    stored: A Boolean indicating if this entity instance is actually stored on
      disk.
  """
  session = None
  key = None
  stored = False
  pub_key = None

  def __init__(self, session, entity, key, name):
    assert isinstance(entity, datastore.Entity)
    self.session = session
    self.key = key
    self.stored = entity.stored
    self.pub_key = name

    if self._props is None:
      for k in entity:
        self.__dict__[k] = entity[k]

    else:
      for p, default in self._props:
        try:
          if entity[p] is None and isinstance(default, list):
            # Callers will expect an iterable, not None
            self.__dict__[p] = []
          else:
            self.__dict__[p] = entity[p]
        except KeyError:
          self.__dict__[p] = default

  @property
  def dict(self):
    rv = {}
    for p, default in self._props:
      if self.__dict__[p] == []:
        # Cannot use [] as a property value
        rv[p] = None
      else:
        rv[p] = self.__dict__[p]
    return rv

class BaseUser(Model):
  _prefix = 'BaseUser:'
  _props = [
      ('passkey', None),
      ('nonce', None),
      ('nextnonce', None),
      ('groups', ['users'])]
  _unindexed = ['passkey','nonce','nextnonce']
  def __init__(self, session, entity, key, name):
    self.username = name
    Model.__init__(self, session, entity, key, name)

class Database(Model):
  _prefix = 'Database:'
  _props = [
      ('owner_acl', []),
      ('manager_acl', []),
      ('user_acl', None)]
  _unindexed = []
  def __init__(self, session, entity, key, name):
    self.name = name
    Model.__init__(self, session, entity, key, name)

class GenDat(Model):
  """## The general user data model type. ##

  Attrs:
    datastore_key: The actual datastore key. It could be an id key, or a name key.
    kind: The datastore kind name for this entity instance.
    key: The hash key pointing to this entity instance in the session
      lookup table.
    _unindexed: A list of properties of this entity instance that will not be
      indexed by the datastore.

  """
  _props = None
  _unindexed = ['textbody']
  # Todo: The db.TextProperty class has a lot of cruft we don't need, but just
  # defining it here as a property on this call is a cheap way to get the
  # functionality we need.
  body = db.TextProperty(name='body', indexed=False)

  def __init__(self, session, entity, query):
    self._props = None
    self.body = query.body
    self.__dict__.update(query.indexes)
    Model.__init__(self, session, entity, query.key, query.name)

  @property
  def dict(self):
    rv = {}
    for k in self.__dict__:
      if k not in ['session','key','stored','_props','_unindexed']:
        rv[k] = self.__dict__[k]
    return rv

class Query(object):
  _class_prefix = 'GenDat:%s:%s'
  _key_prefix = 'GenDat:%s'
  key = None
  class_name = ''
  body = None
  name = None
  indexes = {}

class PutQuery(Query):
  def __init__(self, db_name, stmts):
    self.key = None
    self.class_name = None
    self.body = None
    self.name = ''
    self.indexes = {}

    for s in stmts:
      assert isinstance(s, list), \
          'Query put action statements must be lists.'
      assert len(s) == 3, \
          'Query put action statements must contain 3 tokens.'
      if s[0] == 'key':
        self.name = s[2]
      elif s[0] == 'class':
        self.class_name = self._class_prefix % (db_name, s[2])
      elif s[0] == 'entity':
        self.body = s[2]
      else:
        self.indexes['idx:'+ str(s[0])] = s[2]

    assert isinstance(self.name, basestring) or isinstance(self.name, int), \
        'Query put action must declare a string or integer key.'
    assert isinstance(self.class_name, basestring), \
        'Query put action must declare a class name.'

    self.key = datastore.Key.from_path(
        self.class_name, self._key_prefix % str(self.name))

class KeyQuery(Query):
  def __init__(self, db_name, stmts):
    self.key = None
    self.class_name = None
    self.body = None
    self.name = ''
    self.indexes = {}

    for s in stmts:
      assert isinstance(s, list), \
          'Query put action statements must be lists.'
      assert len(s) == 3, \
          'Query put action statements must contain 3 tokens.'
      if s[0] == 'key':
        self.name = s[2]
      elif s[0] == 'class':
        self.class_name = self._class_prefix % (db_name, s[2])

    assert isinstance(self.name, basestring) or isinstance(self.name, int), \
        'Query put action must declare a string or integer key.'
    assert isinstance(self.class_name, basestring), \
        'Query put action must declare a class name.'

    self.key = datastore.Key.from_path(
        self.class_name, self._key_prefix % str(self.name))

class Session(dict):
  def __init__(self):
    self.__updates = []

  def append_update(self, k):
    if k not in self.__updates:
      self.__updates.append(k)
      return True
    return False

  def remove_update(self, k):
    if k in self.__updates:
      self.__updates.remove(k)

  def __repr__(self):
    d = dict(self)
    rv = '\n<Datastore Session: id:%s,\ndictionary:%s,\n__updates:%s>\n'
    return rv % (id(self), str(d), str(self.__updates))

  @property
  def updates(self):
    return self.__updates

def get_structuredat(session, kind, key_name):
  """### Get a structured type data model. ###

  Args:
    session: A Session abstract datatype instance.
    kind: A reference to a Model class.
    key: A key_name string.
  """

  kname = kind._prefix + key_name
  key = datastore.Key.from_path(kind.__name__, kname)
  try:
    entity = session[key]
  except KeyError:
    try:
      entity = datastore.Get(key)
      entity.stored = True
    except datastore_errors.EntityNotFoundError:
      entity = datastore.Entity(
          kind.__name__,
          name=kname,
          unindexed_properties=kind._unindexed)
      entity.stored = False
    session[key] = entity
  return kind(session, entity, key, key_name)

def get_gendat(session, query):
  """### Get a general data entity. ###

  Args:
    session: A Session abstract datatype instance.
    query: A Query abstract datatype instance.

  """
  assert isinstance(query.key, datastore.Key)
  try:
    entity = session[query.key]
  except KeyError:
    try:
      entity = datastore.Get(query.key)
      entity.stored = True
    except datastore_errors.EntityNotFoundError:
      kname = query.key.name()
      if kname is None:
        entity = datastore.Entity(query.key.kind(),
            unindexed_properties=GenDat._unindexed)
      else:
        entity = datastore.Entity(query.key.kind(), name=kname,
            unindexed_properties=GenDat._unindexed)
      entity.stored = False
    session[query.key] = entity
  model = GenDat(session, entity, query)
  model.body = query.body
  return model

def get(session, model, key=None):
  assert isinstance(session, Session)
  if isinstance(model, Query):
    return get_gendat(session, model)
  if model.__name__ in ['BaseUser', 'Database']:
    # DEBUG
    # rv = get_structuredat(session, model, key)
    # logging.warn("GET %s", repr(session))
    # return rv
    # END DEBUG
    return get_structuredat(session, model, key)
  assert False

def update(model):
  assert isinstance(model, Model)
  # DEBUG
  # logging.warn("DICT %s", repr(model.dict))
  model.session[model.key].update(model.dict)
  model.session.append_update(model.key)
  # DEBUG
  # logging.warn("UPDATE %s", repr(model.session))
  return model

def delete(model):
  assert isinstance(model, Model)
  if not model.stored:
    return
  datastore.Delete(model.key)
  del model.session[model.key]
  model.session.remove_update(model.key)

def commit(session):
  assert isinstance(session, Session)
  # DEBUG
  # logging.warn("COMMIT %s", repr(session))
  datastore.Put([session[k] for k in session.updates])

def gen_put(session, dbname, query):
  put_query = PutQuery(dbname, query)
  model = get(session, put_query)
  model.body = put_query.body
  return update(model)

def gen_delete(dbname, query):
  kq = KeyQuery(dbname, query)
  datastore.Delete(kq.key)
  return kq.name

