"""A utility library of functions used to handle requests."""

import sys
import os
import logging
import wsgiref.util

import webob
from google.appengine.ext.webapp import util
from google.appengine.ext import webapp
from django.utils import simplejson

from rfc822 import formatdate as http_date

"""The number of seconds in a day."""
DAY_SECS = 60 * 60 * 24

"""The number of seconds in a week."""
WEEK_SECS = DAY_SECS * 7

def request():
  env = dict(os.environ)
  env['wsgi.input'] = sys.stdin
  env['wsgi.errors'] = sys.stderr
  env['wsgi.version'] = (1, 0)
  env['wsgi.run_once'] = True
  env['wsgi.url_scheme'] = wsgiref.util.guess_scheme(env)
  env['wsgi.multithread'] = False
  env['wsgi.multiprocess'] = False
  env['HTTP_USER_AGENT'] = env.get('HTTP_USER_AGENT') or 'user-agent'

  return webob.Request(env, charset='utf-8',
      unicode_errors='ignore', decode_param_names=True)

def create_json_response(status=200, message='ok', creds=[], body=None):
  """Utility for creating the JSONResponse text for a DCube protocol request.
  """
  return simplejson.dumps(dict(
      head=dict(status=status, message=message, authorization=creds),
      body=body))

def send_response(log, status, headers, body):
  """Send out an HTTP response.

  Args:
    log: dict of log info for this request.
    status: The HTTP status code.
    headers: dict of HTTP headers.
    body: The body of the HTTP response.

  """
  headers['Content-Length'] = str(len(body))
  logging.info('REQUEST %s %d %s %s',
      (log.get('method') or 'na'),
      (log.get('status') or 0),
      (log.get('warn') or 'ok'),
      (log.get('user-agent') or 'user-agent'))

  util._start_response(
      ('%d %s' %
        (status, webapp.Response.http_status_message(status))),
      headers.items())(body)

