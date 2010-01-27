import os
import sys

from google.appengine.ext import webapp

from rfc822 import formatdate

class Request(object):
  def __init__(self, env):
    try:
      self.body = sys.stdin.read(int(
            env.get('CONTENT_LENGTH', '0')))
    except ValueError:
      self.body = ''

    self.content_type = env.get('CONTENT_TYPE')

def get_environs():
  return dict(os.environ)

def out(status, headers, body):
  print "Status: %s" % ('%d %s' %
      (status, webapp.Response.http_status_message(status)))
  for name, val in headers:
    print "%s: %s" % (name, val)
  print
  # todo: Should we append a newline '\n'??
  sys.stdout.write(body)
  return status, headers, body

def format_header(header):
  head, val = header
  return ('-'.join([s.capitalize() for s in head.split('-')]), val)

def update_headers(default_headers, new_headers):
  default_headers.update(dict(map(format_header, new_headers)))
  return default_headers

def match_url(map, path):
  for regex, part in map:
    match = regex.match(path)
    if match is not None:
      return part, match.groups()

def match_method(map, http_method):
  for method, part in map:
    if http_method == method or method == '*':
      return part

def match_mime(map, accept):
  for mime, part in map:
    if accept.find(mime) or mime == '*':
      return part
  # After checking all the mime types this handler is capable of without a
  # match to the accept header of the user agent, we just use the last handler
  # we have.
  return part

