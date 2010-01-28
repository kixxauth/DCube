import re
import time

import logging

import http
import jsonrequest
import store
import pychap
import groups

class Prototype(object):
  pass

def credentials(head):
  auth = head.get('authorization') or []
  len_auth = len(auth)

  if not isinstance(auth, list) or len_auth is 0:
    return None, None, None, 'No authorization credentials.'

  # auth[0] is username
  if not isinstance(auth[0], basestring):
    return (None, None, None, 'Username \\"%s\\" is invalid.'%
      (auth[0] is None and 'null' or str(auth[0])))

  if len_auth < 3:
    return (auth[0], None, None, 'OK')

  # auth[1] is the cnonce and auth[2] is the response
  if not isinstance(auth[1], basestring):
    return (auth[0], None, None, 'The given cnonce \\"%s\\" is invalid.'%
      (auth[1] is None and 'null' or str(auth[1])))
  if not isinstance(auth[2], basestring):
    return (auth[0], auth[1], None, 'The given response \\"%s\\" is invalid.'%
      (auth[2] is None and 'null' or str(auth[2])))

  return auth[0], auth[1], auth[2], 'OK'

def check_request_creds(dcube_request):
  username, cnonce, response, msg = credentials(dcube_request.head)
  if msg != 'OK':
    return jsonrequest.message_out(401, msg), None

  user = store.get_baseuser(username)
  if user is None:
    return jsonrequest.no_user_out(username), None

  assert user.nonce, 'user.nonce is expected to exist!'
  assert user.nextnonce, 'user.nextnonce is expected to exist!'

  user.cnonce = cnonce
  user.response = response

  return None, user 

def authenticate(dcube_request):
  response, user = check_request_creds(dcube_request)
  if user is None:
    return response, None

  # The user exists, but did not send credentials.
  if user.cnonce is None or user.response is None:
    return (jsonrequest.authenticate_out(user.username, user.nonce, user.nextnonce),
        None)

  auth_user = pychap.authenticate(store.put_baseuser, user)
  if not auth_user.authenticated:
    return (jsonrequest.authenticate_out(
      user.username, auth_user.nonce, auth_user.nextnonce), None)

  return None, auth_user

def jsonrequest_users_get(dcube_request, user_url, user):
  if user is None:
    return jsonrequest.message_out(404, 'User \\"%s\\" could not be found.'% user_url)

  response, auth_user = check_request_creds(dcube_request)
  if auth_user is None:
    return jsonrequest.body_out('{"username":"%s"}'% user.username)

  # If the authenticated user did not send creds.
  if auth_user.cnonce is None or auth_user.response is None:
    return jsonrequest.out(
        creds=[auth_user.username, auth_user.nonce, auth_user.nextnonce],
        body={'username': user.username})

  # Try to authenticate
  authenticated_user = pychap.authenticate(store.put_baseuser, auth_user)
  if authenticated_user.authenticated:
    if auth_user.username == user_url or 'user_admin' in auth_user.groups:
      # The user is requesting their own data or the authenticated user is a
      # member of the 'user_admin' group, so we give it all to them.
      return jsonrequest.out(
          creds=[authenticated_user.username,
                 authenticated_user.nonce,
                 authenticated_user.nextnonce],
          body={'username': user.username, 'groups': user.groups})

  # Limited response for no authentication.
  return jsonrequest.out(
      creds=[authenticated_user.username,
             authenticated_user.nonce,
             authenticated_user.nextnonce],
      body={'username': user.username})

def jsonrequest_users_delete(dcube_request, user_url, target_user):
  if target_user is None:
    return jsonrequest.message_out(404, 'User \\"%s\\" could not be found.'% user_url)

  response, auth_user = authenticate(dcube_request)
  if auth_user is None:
    return response

  store.delete_baseuser(user_url)
  return jsonrequest.message_out(204, 'Deleted user \\"%s\\".'% user_url)

def jsonrequest_users_put(dcube_request, user_url, user):
  if user is None:
    user = Prototype()
    user.username = user_url
    user.groups = ['users']
    new_user = pychap.authenticate(store.put_baseuser, user)
    return jsonrequest.out(status=201, message='Created.',
        creds=[new_user.username,
               new_user.nonce,
               new_user.nextnonce],
        body={'username': new_user.username})

  response, auth_user = authenticate(dcube_request)
  if auth_user is None:
    return response

  if auth_user.username == user.username:
    user = auth_user

  new_groups = dcube_request.body.get('groups')
  if new_groups != user.groups and isinstance(new_groups, list):
    def reduce_level(current_level, group):
      if groups.map[group]['level'] > current_level:
        current_level = groups.map[group]['level']
      return current_level

    level = reduce(reduce_level, auth_user.groups, 0)

    for g in new_groups:
      if not g in user.groups and groups.map[g]['level'] < level:
        user.groups.append(g)

  store.put_baseuser(user)
  return jsonrequest.out(status=200, message='Updated.',
      creds=[user.username,
             user.nonce,
             user.nextnonce],
      body={'username': user.username, 'groups': user.groups})

def jsonrequest_users(request, user_url):
  if not user_url:
    return jsonrequest.message_out(501,
        'The URL \\"/users/\\" is not implemented on this host.')

  dcube_request, http_out = jsonrequest.load(request)
  if dcube_request is None:
    return http_out

  user = store.get_baseuser(user_url)

  return ((dcube_request.head['method'] == 'get' and
            # Implement DCube "get" method.
            jsonrequest_users_get(dcube_request, user_url, user)) or

          (dcube_request.head['method'] == 'put' and
            # Implement DCube "put" method.
            jsonrequest_users_put(dcube_request, user_url, user)) or

          (dcube_request.head['method'] == 'delete' and
            # Implement DCube "delete" method.
            jsonrequest_users_delete(dcube_request, user_url, user)) or

          # No valid method.
          jsonrequest.invalid_method_out(dcube_request.head['method'])
        )

def jsonrequest_root(request):
  dcube_request, http_out = jsonrequest.load(request)
  if dcube_request is None:
    return http_out

  if dcube_request.head['method'] != 'get':
    return jsonrequest.invalid_method_out(dcube_request.head['method'])

  response, user = authenticate(dcube_request)
  if user is None:
    return response

  return jsonrequest.out(
      creds=[user.username, user.nonce, user.nextnonce],
      body='DCube host on Google App Engine.')

def robots(request):
  headers = [
         ('content-type', 'text/plain'),
         ('cache-control', 'public'),
         ('last-modified', 'Fri, 1 Jan 2010 00:00:01 GMT'),
         # Expires in 8 weeks
         ('expires', http.formatdate(time.time() + (604800 * 8)))]
  return 200, headers, 'User-agent: *\nDisallow: /'

MAP = [

    # Root "/" domain url
    (re.compile('^/$'), # Regex to match URL path.
      [
        ('POST', # Matches only the POST HTTP method.
          [
            # Matches only the "application/jsonrequest" MIME type.
            ('application/jsonrequest',
              jsonrequest_root)])]),

    # User management "/users/xyz" urls.
    (re.compile('^/users/(\w*)$'), # Regex to match URL path.
      [
        ('POST', # Matches only the POST HTTP method.
          [
            # Matches only the "application/jsonrequest" MIME type.
            ('application/jsonrequest',
              jsonrequest_users)])]),

    # Web crawling robots take notice:
    (re.compile('/robots\.txt'), # Regex to match URL path.
      [
        ('GET', # Only handles the 'GET' HTTP method.
          [
            ('*', # Matches all accept MIME types.
              robots)])])
    ]

def handle_method(env, methods, matches):
  accept = env.get('HTTP_ACCEPT') or ''
  status, headers, body = http.match_mime(methods, accept)(http.Request(env), *matches)
  default_headers = {
          # Last-Modified right now
          'Last-Modified': http.formatdate(time.time()),
          # Expire time in the near future
          'Expires': http.formatdate(time.time() + 360)
        }
  headers = http.update_headers(default_headers, headers).items()
  http.out(status, headers, body)

def handle_match(env, map, matches):
  req_method = env.get('REQUEST_METHOD')
  # todo: Return 400 response in this case
  assert req_method, 'No HTTP method.'
  methods = http.match_method(map, req_method)
  ((methods is None and
      # Return 'Method Not Alowed' response with a list of allowed methods.
      http.out(405, [('Allow', ','.join([m[0] for m in map]))], '')) or
      
      # Found a handler for the HTTP method.
      handle_method(env, methods, matches))

def main():
  # Get the os environment variables as a dictionary. The os environs are set
  # on every request.
  env = http.get_environs()

  path = env.get('PATH_INFO')
  # todo: Return 400 response in this case
  assert path, 'No PATH_INFO environment variable.'
  match = http.match_url(MAP, path)

  ((match is None and
      # Return 'Not Found' response.
      http.out(404, [
        ('Cache-Control', 'public'),
        # Expires in 8 weeks.
        ('Expires', http.formatdate(time.time() + (604800 * 8)))], '')) or

      # Found a handler for this URL.
      handle_match(env, *match))

if __name__ == '__main__':
  main()
