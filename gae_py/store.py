"""This module contains the models and utility functions for working with the
App Engine datastore.
"""
from google.appengine.ext import db
from google.appengine.api import datastore
from google.appengine.api import datastore_errors

import logging

class Model(object):
  def __init__(self, entity, key):
    self.key = self._prefix + key
    self.stored = entity.stored
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
  def __init__(self, entity, key):
    self.username = key
    Model.__init__(self, entity, key)

class Database(Model):
  _prefix = 'Database:'
  _props = [
      ('owner_acl', []),
      ('manager_acl', []),
      ('user_acl', None)]
  def __init__(self, entity, key):
    self.name = key
    Model.__init__(self, entity, key)

class Session(dict):
  def __init__(self):
    self.__updates = []
  def get(self, kind, key):
    assert kind.__name__ in ['BaseUser', 'Database']
    kname = kind._prefix + key
    try:
      entity = self[kname]
    except KeyError:
      try:
        entity = datastore.Get(datastore.Key.from_path(kind.__name__, kname))
        entity.stored = True
      except datastore_errors.EntityNotFoundError:
        entity = datastore.Entity(kind.__name__, name=kname)
        entity.stored = False
      assert isinstance(entity, dict)
      self[kname] = entity
    return kind(entity, key)

  def update(self, model):
    assert isinstance(model, Model)
    self[model.key].update(model.dict)
    if model.key not in self.__updates:
      self.__updates.append(model.key)
    return model

  def delete(self, model):
    assert isinstance(model, Model)
    datastore.Delete(datastore.Key.from_path(
      model.__class__.__name__, model.key))
    del self[model.key]
    if model.key in self.__updates:
      self.__updates.remove(model.key)

  @property
  def updates(self):
    return self.__updates

  def __repr__(self):
    d = dict(self)
    rv = '\n<Datastore Session: id:%s,\ndictionary:%s,\n__updates:%s>\n'
    return rv % (id(self), str(d), str(self.__updates))

def commit(session):
  assert isinstance(session, Session)
  # DEBUG logging.warn("COMMIT %s", repr(session))
  datastore.Put([session[k] for k in session.updates])
