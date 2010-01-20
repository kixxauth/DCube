import httplib
import hashlib

HOST = None
LOCAL = True
ADMIN_USERNAME = None
ADMIN_PASSKEY = None

class Prototype(object):
  pass

def make_http_request(method='POST', url='/', body=None, headers={}):
  cxn = httplib.HTTPConnection(HOST)
  cxn.request(method, url, body, headers)
  response = cxn.getresponse()
  rv = Prototype()
  rv.status = response.status
  rv.message = response.reason
  rv.headers = dict(response.getheaders())
  rv.body = response.read()
  cxn.close()
  return rv

def create_credentials(passkey, username, nonce, nextnonce):
  """Takes passkey, nonce, nextnonce and returns a tuple;
  (username, cnonce, response)
  """
  def hash(s):
    return hashlib.sha1(s).hexdigest()

  def cnonce(key):
    return hash(hash(key))

  def response(key):
    return hash(key)

  def juxt(passkey, seed):
    return str(passkey) + str(seed)

  return (username,
      cnonce(juxt(passkey, nextnonce)),
      response(juxt(passkey, nonce)))

def setup(host, local, username, passkey):
  global HOST
  global LOCAL
  global ADMIN_USERNAME
  global ADMIN_PASSKEY

  HOST = host
  LOCAL = local
  ADMIN_USERNAME = username
  ADMIN_PASSKEY = passkey
