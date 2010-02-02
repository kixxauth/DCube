import os
import re
import sys
import time
import logging

from google.appengine.ext import webapp

from rfc822 import formatdate

class SessionStop(Exception):
  status = 200
  headers = []
  body = None
  def __init__(self, status=200, headers=[], body=None):
    assert isinstance(status, int)
    self.status = status
    assert isinstance(headers, list)
    self.headers = headers
    assert body is None or isinstance(body, basestring)
    if body != 0:
      self.body = body or ''
    else:
      self.body = '0'

class PathHandler(dict):
  def __init__(self, pairs=[]):
    assert isinstance(pairs, list)
    for pair in pairs:
      assert len(pair) == 2
      self.__setitem__(*pair)

  def __setitem__(self, method, handler):
    assert isinstance(method, basestring)
    assert callable(handler)
    k = method.upper()
    dict.__setitem__(self, k, handler)

  def __getitem__(self, k):
    return self.get(k)

  def get(self, k):
    method = k.upper()
    return dict.get(self, method)

class PathMapping(list):
  def __init__(self, pairs=[]):
    assert isinstance(pairs, list)
    for pair in pairs:
      assert len(pair) == 2
      self.append(*pair)

  def append(self, regex, handler):
    assert isinstance(handler, PathHandler)
    assert isinstance(regex, basestring)
    if not regex.startswith('^'):
      regex = '^' + regex
    if not regex.endswith('$'):
      regex += '$'
    rx = re.compile(regex)
    list.append(self, (rx, handler))

class PathMatch(object):
  handler = None
  path_matches = ()
  def __init__(self, handler, matched_groups):
    assert isinstance(handler, PathHandler)
    assert isinstance(matched_groups, tuple)
    self.handler = handler
    self.path_matches = matched_groups

class Request(object):
  body = ''
  path_matches = None
  content_type = ''
  def __init__(self, path_matches):
    try:
      self.body = sys.stdin.read(int(
            os.environ['CONTENT_LENGTH']))
    except ValueError:
      pass

    self.content_type = os.environ['CONTENT_TYPE']

    if not (len(path_matches) == 0 or path_matches[0] == ''):
      self.path_matches = path_matches

def out(httpout):
  print "Status: %s" % ('%d %s' %
      (httpout.status, webapp.Response.http_status_message(httpout.status)))
  for name, val in httpout.headers:
    print "%s: %s" % (name, val)
  print
  # todo: Should we append a newline '\n'??
  sys.stdout.write(httpout.body)
  return httpout

def format_header(header):
  head, val = header
  return ('-'.join([s.capitalize() for s in head.split('-')]), val)

def update_headers(default_headers, new_headers):
  default_headers.update(dict(map(format_header, new_headers)))
  return default_headers

def dispatch_method(pathmatch):
  method = os.environ['REQUEST_METHOD']
  handler = pathmatch.handler.get(method)
  if callable(handler):
    return handler(Request(pathmatch.path_matches))

  headers = [('Allow', ','.join(pathmatch.handler.keys()))]
  raise SessionStop(status=405, headers=headers, body=None)

def match_path(mapping):
  path = os.environ['PATH_INFO']
  for regex, handler in mapping:
    match = regex.match(path)
    if match is not None:
      return PathMatch(handler, match.groups())

  headers = [
        ('Cache-Control', 'public'),
        # Expires in 8 weeks.
        ('Expires', formatdate(time.time() + (604800 * 8)))]

  raise SessionStop(status=404, headers=headers, body=None)
