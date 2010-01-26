from django.utils import simplejson

class JSONRequest(object):
  def __init__(self, head, body):
    self.head = head
    self.body = body

def load(request):
  # The "Content-Type" header on the request must be application/jsonrequest.
  if request.content_type != 'application/jsonrequest':
    return None, (415, [('Content-Type', 'text/plain')],
        'Server accepts Content-Type "application/jsonrequest".')

  # We only accept valid JSON text in the request body
  json = None
  try:
    json = simplejson.loads(request.body)
  except: # todo: What error do we want to catch?
    return None, (400, [('Content-Type', 'text/plain')],
        'Invalid JSON text body : (%s)'% request.body)

  # Only the {} dict object is acceptable as a message payload for the DCube
  # protcol.
  if not isinstance(json, dict):
    return None, (400, [('Content-Type', 'text/plain')],
        'Invalid JSON text body : (%s)'% request.body)

  # The head of the request must be a dictionary.
  if not isinstance(json.get('head'), dict):
    return None, (400, [('Content-Type', 'text/plain')],
        'Missing DCube message "head" in (%s)'% request.body)

  # The head must contain a method entry.
  if not isinstance(json['head'].get('method'), basestring):
    return None, (400, [('Content-Type', 'text/plain')],
        'Missing DCube message header "method" in (%s)'% request.body)

  return JSONRequest(json['head'], json.get('body')), None

def invalid_method_out(method):
  return message_out(405, 'Invalid method \\"%s\\".'% method)

def no_user_out(username):
  return message_out(401, 'Username \\"%s\\" does not exist.'% username)

def valid_out(body):
  return (200, [('Content-Type', 'application/jsonrequest')], body)

def message_out(status, message):
  return valid_out('{"head":{"status":%d,"message":"%s"}}'% (status, message))

def authorization_out(status, message, username, nonce, nextnonce):
  return valid_out('{"head":{"status":%d,"message":"%s",'
      '"authorization":["%s","%s","%s"]}}'%
      (status, message, username, nonce, nextnonce))

def authenticate_out(username, nonce, nextnonce):
  return authorization_out(401, 'Authenticate.', username, nonce, nextnonce)

def out(status=200, message='OK', creds=[], body=None):
  return valid_out(simplejson.dumps(dict(
    head=dict(status=status,
              message=message,
              authorization=creds),
    body=body)))
