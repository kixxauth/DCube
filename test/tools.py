import httplib
import yaml

def checkhost(url):
  cxn = httplib.HTTPConnection(url)
  try:
    cxn.request('GET', '/')
    return True
  except httplib.socket.error:
    return False

def getconfigs(path):
  """Takes the path to app.yaml and returns the current app version number.
  """
  return yaml.load(open(path))
