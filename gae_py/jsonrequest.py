import dcube_types
import http
from django.utils import simplejson

SessionStop = http.SessionStop

def load(request):
  """### Parse and validate an HTTP JSON formatted DCube request. ###

  If any part of the HTTP request cannot be parsed or is invalid an
  http.SessionStop instance is raised, fully populated and ready for output.

  Otherwise a dcube_types.Request instance is returned.

  args:
    request: An http.Request instance (abstract data type)

  returns:
    A dcube_types.Request instance (abstract data type)

  raises:
    A populated http.SessionStop instance (abstract data type) on failure.

  """

  # The "Content-Type" header on the request must be application/jsonrequest.
  if request.content_type != 'application/jsonrequest':
    raise SessionStop(status=415,
                headers=[('Content-Type', 'text/plain')],
                body='Server accepts Content-Type "application/jsonrequest".')

  # We only accept valid JSON text in the request body
  json = None
  try:
    json = simplejson.loads(request.body)
  except: # todo: What error do we want to catch?
    raise SessionStop(status=400,
                headers=[('Content-Type', 'text/plain')],
                body='Invalid JSON text body : (%s)'% request.body)

  # Only the {} dict object is acceptable as a message payload for the DCube
  # protcol.
  if not isinstance(json, dict):
    raise SessionStop(status=400,
                headers=[('Content-Type', 'text/plain')],
                body='Invalid JSON text body : (%s)'% request.body)

  # The head of the request must be a dictionary.
  if not isinstance(json.get('head'), dict):
    raise SessionStop(status=400,
                headers=[('Content-Type', 'text/plain')],
                body='Missing DCube message "head" in (%s)'% request.body)

  # The head must contain a method entry.
  if not isinstance(json['head'].get('method'), basestring):
    raise SessionStop(status=400,
                headers=[('Content-Type', 'text/plain')],
                body='Missing DCube message header "method" in (%s)'% request.body)

  return dcube_types.Request(json['head'], json.get('body'))

def httpout(body):
  """Raises a SessionStop exception populated with default HTTP output."""
  raise SessionStop(status=200,
              headers=[('Content-Type', 'application/jsonrequest')],
              body=body)

def message_out(status, message):
  """Send out the status a message parts of a JSON response."""
  httpout('{"head":{"status":%d,"message":"%s"}}'% (status, message))

def invalid_method_out(method):
  """Send out an invalid DCube method response. """
  message_out(405, 'Invalid method \\"%s\\".'% method)

def no_user_out(username):
  """Send out a missing DCube user response. """
  message_out(401, 'Username \\"%s\\" does not exist.'% username)

def authorization_out(status, message, username, nonce, nextnonce):
  """Just send back the DCube authorization header with status and message."""
  httpout('{"head":{"status":%d,"message":"%s",'
      '"authorization":["%s","%s","%s"]}}'%
      (status, message, username, nonce, nextnonce))

def authenticate_out(username, nonce, nextnonce):
  """Send back an authenticate response with CHAP nonce and nextnonce."""
  authorization_out(401, 'Authenticate.', username, nonce, nextnonce)

def body_out(body):
  """Send out a DCube 200 status message with only the body."""
  httpout('{"head":{"status":200,"message":"OK"},"body":%s}'% body)

def out(status=200, message='OK', creds=[], body=None):
  """Send out a full DCube response in JSONRequest format."""
  httpout(simplejson.dumps(dict(
    head=dict(status=status,
              message=message,
              authorization=creds),
    body=body)))
