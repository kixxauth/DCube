import hashlib
import httplib
import simplejson

HOST = 'localhost'
LOCALHOST = 'localhost'
USERNAME = None
PASSKEY = None

def set_HOST(val):
  global HOST
  HOST = val

def set_LOCALHOST(val):
  global LOCALHOST
  LOCALHOST = val

def set_USERNAME(val):
  global USERNAME
  USERNAME = val

def set_PASSKEY(val):
  global PASSKEY 
  PASSKEY = val

def getJSONRequestHeaders(content_type='application/jsonrequest',
                          accept='application/jsonrequest',
                          user_agent='testing_client'):
  return {
    'Content-Type': content_type,
    'Accept': accept,
    'User-Agent': user_agent}

def httpConnection():
  return httplib.HTTPConnection(HOST)

# todo: get the server header for the live server
def defaultHeaders(content_length='0',
                   content_type='application/jsonrequest',
                   cache_control='no-cache',
                   expires='-1'):
  """Returns a set of headers expected by default from the DCube host server,
  but can be configured by passing different keyed parameters.
  """
  return {'content-type': content_type,
          'content-length': content_length,
          'server':(HOST is LOCALHOST and 'Development/1.0' or 'foo'),
          'date': False,
          'cache-control': cache_control,
          'expires': expires}

def checkHeaders(headers, expected):
  """Check each (name, value) pair in the given headers against the given
  expected dictionary. If the named header in the expected dictionary is False,
  it is skipped.  Skipping is useful for hard to test headers like the date
  header.
  """
  for name, val in headers:
    if expected.get(name) is False:
      continue
    assert (val == expected.get(name)), \
        ('header %s: %s is not %s' % (name, val, expected.get(name)))

def createJSONRequest(method='get', creds=[], body=None):
  """Create the JSON encoded body of a JSONRequest"""
  return simplejson.dumps(dict(
      head=dict(method=method, authorization=creds),
      body=body))

def makeJSONRequest_for_httplib(url='/', method='get', creds=[], body=None):
  """return a tuple that can be unpacked as the arguments to
  httplib.Connection().request()"""
  return ('POST', url,
      createJSONRequest(method, creds, body), getJSONRequestHeaders())

def createCredentials(passkey, username, nonce, nextnonce):
  """Takes passkey, nonce, nextnonce and returns a list;
  [username, cnonce, response]
  """
  def hash(s):
    return hashlib.sha1(s).hexdigest()

  def cnonce(key):
    return hash(hash(key))

  def response(key):
    return hash(key)

  def juxt(passkey, seed):
    return str(passkey) + str(seed)

  return [username,
      cnonce(juxt(passkey, nextnonce)),
      response(juxt(passkey, nonce))]

def makeRequest(url='/', method='get', creds=[]):
  cxn = httpConnection()
  req = makeJSONRequest_for_httplib(
        url=url, method=method, creds=creds)
  cxn.request(*req)
  res = cxn.getresponse().read()
  rv = simplejson.loads(res)
  cxn.close()
  return rv
