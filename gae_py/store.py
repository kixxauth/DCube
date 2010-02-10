"""This module contains the models and utility functions for working with the
App Engine datastore.
"""
import logging

from google.appengine.ext import db
from google.appengine.api import datastore
from google.appengine.api import datastore_errors

class Model():
  pass

class BaseUser(db.Model):
  __prefix = 'BaseUser:'
  passkey = db.StringProperty(indexed=False)
  nonce = db.StringProperty(indexed=False)
  nextnonce = db.StringProperty(indexed=False)
  groups = db.StringListProperty(default=['users'])

  """
  @classmethod
  def create_key(name):
    return db.Key.from_path(
        self.__class__.__name__, self.__prefix + str(name))
        """

  @classmethod
  def get(cls, name):
    return db.get(db.Key.from_path(
        cls.__name__, cls.__prefix + str(name)))

class Database(db.Model):
  __prefix = 'Database:'
  owner_acl = db.StringListProperty()
  manager_acl = db.StringListProperty()
  user_acl = db.StringListProperty()

  @classmethod
  def get(cls, name):
    return db.get(db.Key.from_path(
        cls.__name__, cls.__prefix + str(name)))

def update(model):
  assert isinstance(model, db.Model)
  model.put()

class Session(object):
  __instances = {}
  __updates = []
  key_type = db.Key
  model_type = db.Model
  def __init__(self):
    self.__instances = {}
    self.__updates = []

  def get_entity(self, k):
    return self.__instances.get(k)

  def append_entity(self, k, v):
    Session.validate((k, self.key_type), (v, self.model_type))
    self.__instances[k] = v
    return v

  def update_entity(self, k, v):
    Session.validate((k, self.key_type), (v, self.model_type))
    self.__instances[k] = v
    if k not in self.__updates:
      self.__updates.append(k)
    return v

  def remove_entity(self, k, v):
    Session.validate((k, self.key_type), (v, self.model_type))
    assert self.__instances.get(k) is not None
    if k in self.__updates:
      self.__updates.remove(k)
    del self.__instances[k]

  @staticmethod
  def validate(k, v):
    assert isinstance(*k)
    assert isinstance(*v)

class Action(object):
  __keywords = []

  @classmethod
  def normalize_statements(cls, stmts):
    named_props = {}
    index_list = []
    for s in stmts:
      assert isinstance(s, list), \
          'Query put action statements must be lists.'
      assert len(s) == 3, \
          'Query put action statements must contain 3 tokens.'
      assert isinstance(s[0], basestring), \
          'The first token in an action statement must be a string.'

      if s[0] in cls.keywords:
        named_props[s[0]] = s[2]
      else:
        index_list.append((cls is QueryAction and
          ('%s %s'%(s[0], s[1]), s[2])) or (s[0], s[2]))
    return (named_props, index_list)

class PutAction(Action):
  __keywords = ['key','entity']

class GetAction(Action):
  __keywords = ['key']

class DeleteAction(Action):
  __keywords = ['key']

class QueryAction(Action):
  __keywords = []

class BaseModel(db.Model):
  def init_session(self, session):
    try:
      assert self.__session
    except AttributeError:
      assert isinstance(session, Session)
      k = self.key()
      assert k is not None
      assert session.get_entity(k) is None, \
          'Entity %s has already been set for this session.'% repr(k)
      session.append_entity(k, self)
      self.__session = session
      return self
    else:
      assert False, \
          'Cannot set the session more than once on a BaseModel instance.'

  def put(self):
    assert isinstance(self.__session, Session), \
        'BaseModel.init_session() must be called before BaseModel.put().'
    return self.__session.update_entity(self.key(), self)

  def delete(self):
    assert isinstance(self.__session, Session), \
        'BaseModel.init_session() must be called before BaseModel.delete().'
    db.delete(self)
    self.__session.remove_entity(self)

  def get(self, *args, **kwargs):
    return self

  @classmethod
  def sanitize_key_name(cls, name):
    logging.warn('SANITIZE_PREFIX %s:%s', cls.__prefix, name)
    assert cls.__prifix in ['BaseUser:','Database:','GeneralData:']
    return cls.__prefix + str(name)

  @classmethod
  def select(cls, name):
    assert cls.__name__ in ['BaseUser','Database']
    return cls.get_by_key_name(cls.sanitize_key_name(name))

  @classmethod
  def create(cls, name):
    assert cls.__name__ in ['BaseUser','Database']
    return cls(key=(cls.__name__, cls.sanitize_key_name(name)))

class BaseUser(BaseModel):
  __prefix = 'BaseUser:'
  passkey = db.StringProperty(indexed=False)
  nonce = db.StringProperty(indexed=False)
  nextnonce = db.StringProperty(indexed=False)
  groups = db.StringListProperty(default=['users'])

class Database(BaseModel):
  __prefix = 'Database:'
  owner_acl = db.StringListProperty()
  manager_acl = db.StringListProperty()
  user_acl = db.StringListProperty()

  def __init__(self, *args, **kwargs):
    self.__actions = []
    BaseModel.__init__(self, *args, **kwargs)

  def append_action(self, action, stmts):
    self.__actions.append()

  @property
  def results(self):
    def get_result():
      pass
    def put_result():
      pass
    def delete_result():
      pass
    def query_result():
      pass

class GeneralData(db.Expando):
  __prefix = 'GeneralData:'
  text_body = db.TextProperty()

def get(session, model_class, key_name):
  assert isinstance(session, Session)
  entity = model_class.select(key_name)
  if entity is None:
    entity = model_class.create(key_name)
  return entity.init_session(session)

def update(session, entity):
  assert isinstance(session, Session)
  assert isinstance(entity, BaseModel)
  return session.update_entity(entity.key(), entity)

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
    # DEBUG 
    # logging.warn('DECLARE_BODY %s', self.body)
    self.__dict__.update(query.indexes)
    Model.__init__(self, session, entity, query.key, query.name)

  @property
  def dict(self):
    rv = {}
    for k in self.__dict__:
      if k not in ['class_name','pub_key','session','key','stored','_props','_unindexed']:
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
    self.given_class = None
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
        self.given_class = s[2]
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
    self.given_class = None
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
        self.given_class = s[2]
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

class GenDat(Model):
  kind = 'GeneralData'
  unindexed_properties = ['_body', 'body']

  # Todo: The db.TextProperty class has a lot of cruft we don't need, but just
  # defining it here as a property on this call is a cheap way to get the
  # functionality we need.
  body = db.TextProperty(name='body', indexed=False)

  def __init__(self, session, key):
    assert isinstance(key, datastore.Key)
    try:
      entity = session[key]
    except KeyError:
      try:
        entity = datastore.Get(key)
      except datastore_errors.EntityNotFoundError:
        entity = datastore.Entity(self.kind, name=name,
            unindexed_properties=self.unindexed_properties)
      session[key] = entity

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

def _get(session, model, key=None):
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

def get_gendat(session, key, name):
  """### Get a general data entity. ###

  Args:
    session: A Session abstract datatype instance.
    query: A Query abstract datatype instance.

  """

def gen_get(dbname, query):
  kq = KeyQuery(dbname, query)
  # DEBUG
  # logging.warn('GET_KEY-KIND %s / %s', kq.key.id_or_name(), kq.key.kind())
  rv = {
      'class': kq.given_class,
      'key': kq.name,
      'indexes': {},
      'entity': None,
      'stored': False}
  try:
    entity = datastore.Get(kq.key)
  except datastore_errors.EntityNotFoundError:
    return rv

  rv['stored'] = True
  for k in entity:
    if k != '_body':
      rv['indexes'][k.replace('idx:', '')] = entity[k]
  # DEBUG
  # logging.warn('BODY %s', entity.get('_body'))
  rv['entity'] = entity.get('_body')
  return rv

def gen_put(session, dbname, query):
  put_query = {}
  for s in stmts:
    assert isinstance(s, list), \
        'A query action statement must be a list.'
    assert len(s) == 3, \
        'A query action statement must contain 3 tokens.'
    if s[0] == 'key' or s[0] == 'entity':
      put_query[s[0]] = s[2]
    else:
      # todo: The index name should be sanitized in a central location.
      put_query['idx:'+ str(s[0])] = s[2]

  model = get(session, put_query)
  # model.body = put_query.body
  return update(model)

def gen_delete(dbname, query):
  kq = KeyQuery(dbname, query)
  datastore.Delete(kq.key)
  return kq.name, kq.given_class

def get_query():
  pass

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

