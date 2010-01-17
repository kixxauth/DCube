import httplib

HOST = None

class Prototype(object):
  pass

def make_http_request(method, url, body, headers):
  cxn = httplib.HTTPConnection(HOST)
  cxn.request(method, url, body, headers)
  response = cxn.getresponse()
  rv = Prototype()
  rv.status = response.status
  rv.message = response.reason
  rv.headers = response.getheaders()
  rv.body = response.read()
  cxn.close()
  return rv

def setup(host):
  global HOST

  HOST = host
