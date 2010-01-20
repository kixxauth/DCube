"""Set up the sys-admin test user for local automated testing."""

#######################################################################
#
#   Do not fuck with with this handler! (it is a big security issue)  #
#
#######################################################################

import os
import logging

def respond(status, body):
  print 'Status: %s'% status
  print 'Content-Type: text/plain'
  print 'Content-Length: %d' % len(body)
  print 'Expires: -1'
  print 'Cache-Control: private'
  print
  print body 

def main():
  TEMP_TEST_USERNAME = 'TEMP_INSECURE_USER'

  http_method = os.environ['REQUEST_METHOD']

  if http_method == 'GET':
    respond('200 OK', TEMP_TEST_USERNAME)
    return

  # Check to see if we are on the local dev_appserver.
  # If not, we bail!
  if not os.environ['SERVER_SOFTWARE'].startswith('Development'):
    respond('403 Forbidden','')
    return

  logging.critical('/testsetup has been accessed')

  # This is the only handler script where we should ever see this import.
  import store

  if http_method == 'PUT':
    user = store.get_baseuser(TEMP_TEST_USERNAME)
    if user is None:
      user = type('Proto', (object,),
          {'username': TEMP_TEST_USERNAME,
           'groups': ['users', 'sys_admin']})()
      import pychap
      pychap.authenticate(store.put_baseuser, user)

    respond('200 OK', TEMP_TEST_USERNAME)

  elif http_method == 'DELETE':
    store.delete_baseuser(TEMP_TEST_USERNAME)
    respond('204 No Content', '')

  else:
    respond('405 Method Not Allowed','')


if __name__ == '__main__':
  main()
