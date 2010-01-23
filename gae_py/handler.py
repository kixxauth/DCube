import os
import sys
import re
import time

import logging

from rfc822 import formatdate as http_date
from google.appengine.ext import webapp
from django.utils import simplejson

class Proto(object):
  def __init__(self, attrs):
    self.__dict__ = attrs

class Response(Proto):
  pass

class Request(Proto):
  pass

class ResponseHeaders():
  def __init__(self, headers):
    self.__headers = {}
    self.update(headers)

  @staticmethod
  def format_header(header):
    head, val = header
    return ('-'.join([s.capitalize() for s in head.split('-')]), val)

  def update(self, headers):
    self.__headers.update(
        dict(
          map(self.format_header, headers)))

  @property
  def out(self):
    return self.__headers.items()

class Session(object):
  def __init__(self, env):
    headers = [
          # Last-Modified right now
          ('Last-Modified', http_date(time.time())),
          # Expire time in the near future
          ('Expires', http_date(time.time() + 360))
        ]

    try:
      body = sys.stdin.read(int(
            os.environ.get('CONTENT_LENGTH', '0')))
    except ValueError:
      body = ''

    self.response = Response({
      'status': 200,
      'headers': ResponseHeaders(headers),
      'body': ''})

    self.request = Request({
      'content_type': env.get('CONTENT_TYPE'),
      'body': body})

  def write(self):
    http_out(self.response.status,
             self.response.headers.out,
             self.response.body)

class JSONRequest(object):
  def __init__(self, session):
    self.http = session

    # The "Content-Type" header on the request must be application/jsonrequest.
    if self.http.request.content_type != 'application/jsonrequest':
      self.http.response.status = 415
      self.valid = False
      return

    # We only accept valid JSON text in the request body
    json = None
    try:
      json = simplejson.loads(self.http.request.body)
    except: # todo: What error do we want to catch?
      self.http.response.status = 400
      self.http.response.headers.update([('content-type', 'text/plain')])
      self.http.response.body = ('Invalid JSON text body : (%s)\n'%
          self.http.request.body)
      self.valid = False
      return

    # Only the {} dict object is acceptable as a message payload for the DCube
    # protcol.
    if not isinstance(json, dict):
      self.http.response.status = 400
      self.http.response.headers.update([('content-type', 'text/plain')])
      self.http.response.body = ('Invalid JSON text body : (%s)\n'%
          self.http.request.body)
      self.valid = False
      return

    # Create the body object according to the DCube protocol.
    if not isinstance(json.get('head'), dict):
      self.http.response.status = 400
      self.http.response.headers.update([('content-type', 'text/plain')])
      self.http.response.body = ('Missing DCube message "head" in (%s)'%
          self.http.request.body)
      self.valid = False
      return

    if not isinstance(json['head'].get('method'), basestring):
      self.http.response.status = 400
      self.http.response.headers.update([('content-type', 'text/plain')])
      self.http.response.body = ('Missing DCube message header "method" in (%s)'%
          self.http.request.body)
      self.valid = False
      return

    json['head']['method'] = json['head']['method'].lower()
    self.request = Request({'head': json['head'], 'body': json.get('body')})
    self.response = Response({'head': {'status': 200, 'message': 'OK'}, 'body': None})
    self.valid = True

  def write(self):
    if self.valid:
      http_out(self.http.response.status,
               self.http.response.headers.out,
               simplejson.dumps({'head': self.response.head, 'body': self.response.body}))
    else:
      http_out(self.http.response.status,
               self.http.response.headers.out,
               self.http.response.body)

def robots(session):
  session.response.headers.update([
               ('content-type', 'text/plain'),
               ('cache-control', 'public'),
               ('last-modified', 'Fri, 1 Jan 2010 00:00:01 GMT'),
               # Expires in 8 weeks
               ('expires', http_date(time.time() + (604800 * 8)))])
  session.response.body = 'User-agent: *\nDisallow: /'
  return session

def root(session):
  session = JSONRequest(session)
  if not session.valid:
    return session

  # The root '/' url only accepts the 'get' DCube method
  if session.request.head['method'] != 'get':
    session.response.head['status'] = 405
    session.response.head['message'] = ('Invalid method "%s".'%
        session.request.head['method'])
    return session
  return session

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
              root)])])
    ]

def http_out(status, headers, body):
    print "Status: %s" % ('%d %s' %
        (status, webapp.Response.http_status_message(status)))
    for name, val in headers:
      print "%s: %s" % (name, val)
    print
    sys.stdout.write(body)

def handle_request(env, handler):
  handler(Session(env)).write()

def handle_mime(env, mimes):
  accept = env.get('HTTP_ACCEPT') or ''
  for mime, handler in mimes:
    if accept.find(mime) or mime == '*':
      handle_request(env, handler)
      return
  # After checking all the mime types this handler is capable of without a
  # match to the accept header of the user agent, we just use the last handler
  # we have.
  handle_request(env, handler)

def handle_method(env, methods):
  req_method = env.get('REQUEST_METHOD')
  assert req_method, 'No HTTP method.'
  for method, mimes in methods:
    if method == req_method or method == '*':
      handle_mime(env, mimes)
      return
  http_out(405, [('Allow', ','.join([m[0] for m in methods]))], '')

def main():
  env = dict(os.environ)
  path = env.get('PATH_INFO')
  assert path, 'No PATH_INFO environment variable.'
  for regex, methods in MAP:
    if regex.match(path):
      handle_method(env, methods)
      return

  headers = [
      ('Cache-Control', 'public'),
      # Expires in 8 weeks.
      ('Expires', http_date(time.time() + (604800 * 8)))]
  http_out(404, headers, '')


if __name__ == '__main__':
  main()
