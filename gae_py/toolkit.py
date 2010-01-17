"""A utility library of functions used to handle requests."""

import sys
import os
import logging
import wsgiref.util

import webob
from google.appengine.ext.webapp import util
from google.appengine.ext import webapp

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

  return webob.Request(env, charset='utf-8',
      unicode_errors='ignore', decode_param_names=True)

def send_response(log, status, headers, body):
  """Send out an HTTP response.

  Args:
    log: dict of log info for this request.
    status: The HTTP status code.
    headers: dict of HTTP headers.
    body: The body of the HTTP response.

  """
  logging.info('REQUEST %s %d %s',
      (log.get('method') or 'na'),
      (log.get('status') or 0),
      (log.get('warn') or 'ok'))
  util._start_response(
      ('%d %s' %
        (status, webapp.Response.http_status_message(status))),
      headers.items())(body)

