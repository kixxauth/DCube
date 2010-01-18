import httplib

HOST = None
LOCAL = True

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

def setup(host, local):
  global HOST
  global LOCAL

  HOST = host
  LOCAL = local
