import httplib

def make_request(url, post):
  if url.startswith('http://'):
    url = url.replace('http://', '', 1).split('/', 1)
  elif url.startswith('https://'):
    url = url.replace('https://', '', 1).split('/', 1)
  else:
    url = url.split('/', 1)

  cxn = httplib.HTTPConnection(url[0])
  del url[0]
  cxn.request((post and 'POST' or 'GET'),
              (len(url) and ('/'+ url[0]) or '/'),
              post,
              {'Content-Type':'application/jsonrequest',
               'Accept': 'application/jsonrequest'})

  r = cxn.getresponse()
  bod = r.read()
  cxn.close()
  return bod

def post(url, send):
  """Takes a full url and JSON encoded string for a POST request."""
  return make_request(url, send)

def get(url):
  """Takes a full url and makes a GET request on it."""
  return make_request(url, None)
