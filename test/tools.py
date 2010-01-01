import os
import hashlib
import httplib
import yaml

def checkhost(url):
  cxn = httplib.HTTPConnection(url)
  try:
    cxn.request('GET', '/')
    return True
  except httplib.socket.error:
    return False

def getconfigs(dir):
  """Takes the path to the root app directory and returns the current app
  configs as parsed by PyYaml.
  """
  return yaml.load(open(os.path.join(dir, 'app.yaml')))

def hash(s):
  return hashlib.md5(s).hexdigest()

def cnonce(key):
  return hash(hash(key))

def response(key):
  return hash(key)

def juxt(passkey, seed):
  return str(passkey) + str(seed)

def createCredentials(passkey, nonce, nextnonce):
  """Takes passkey, nonce, nextnonce and returns a tuple;
  passkey, cnonce, response
  """
  return (passkey,
      cnonce(juxt(passkey, nextnonce)),
      response(juxt(passkey, nonce)))
