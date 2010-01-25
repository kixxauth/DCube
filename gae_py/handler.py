import re
import time

import logging

import http
import jsonrequest

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

def jsonrequest_root(request):
  dcube_request, http_out = jsonrequest.load(request)
  if dcube_request is None:
    return http_out

  if dcube_request.head['method'] != 'get':
    return jsonrequest.invalid_method_out(dcube_request.head['method'])

  username, cnonce, response, msg = credentials(dcube_request.head)
  if msg != 'OK':
    return jsonrequest.message_out(401, msg)

def robots(request):
  headers = [
         ('content-type', 'text/plain'),
         ('cache-control', 'public'),
         ('last-modified', 'Fri, 1 Jan 2010 00:00:01 GMT'),
         # Expires in 8 weeks
         ('expires', http.formatdate(time.time() + (604800 * 8)))]
  return 200, headers, 'User-agent: *\nDisallow: /'

MAP = [

    # Web crawling robots take notice:
    (re.compile('/robots\.txt'), # Regex to match URL path.
      [
        ('GET', # Matches all HTTP methods.
          [
            ('*', # Matches all accept MIME types.
              robots)])]),

    # Root "/" domain url
    (re.compile('^/$'), # Regex to match URL path.
      [
        ('POST', # Matches all HTTP methods.
          [
            ('application/jsonrequest', # Matches all accept MIME types.
              jsonrequest_root)])])
    ]

def main():
  # Get the os environment variables as a dictionary. The os environs are set
  # on every request.
  env = http.get_environs()

  path = env.get('PATH_INFO')
  # todo: Return 400 response in this case
  assert path, 'No PATH_INFO environment variable.'
  match = http.match_url(MAP, path)
  if match is None:
    # Return 'Not Found' response.
    http.out(404, [
        ('Cache-Control', 'public'),
        # Expires in 8 weeks.
        ('Expires', http.formatdate(time.time() + (604800 * 8)))], '')
    return
  map, matched_groups = match

  req_method = env.get('REQUEST_METHOD')
  # todo: Return 400 response in this case
  assert req_method, 'No HTTP method.'
  methods = http.match_method(map, req_method)

  if methods is None:
    # Return 'Method Not Alowed' response with a list of allowed methods.
    http.out(405, [('Allow', ','.join([m[0] for m in map]))], '')
    return

  accept = env.get('HTTP_ACCEPT') or ''
  status, headers, body = http.match_mime(methods, accept)(http.Request(env))
  default_headers = {
          # Last-Modified right now
          'Last-Modified': http.formatdate(time.time()),
          # Expire time in the near future
          'Expires': http.formatdate(time.time() + 360)
        }
  headers = http.update_headers(default_headers, headers).items()
  http.out(status, headers, body)

if __name__ == '__main__':
  main()
