"""Set up the sys-admin, user-admin, account-admin, and database level test
users for remote automated testing.
"""
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
  # Check to see if we are on the local dev_appserver.
  # If not, we bail!
  if not os.environ['SERVER_SOFTWARE'].startswith('Development'):
    respond('403 Forbidden','')
    return

  logging.critical('/testsetup has been accessed')

  http_method = os.environ['REQUEST_METHOD']

  users = [
        ('test_sys_admin', 'sys_admin'),
        ('test_user_admin', 'user_admin'),
        ('test_account_admin', 'account_admin'),
        ('test_database_admin', 'database')
      ]

  # This is the only handler script where we should ever see this import.
  import store

  if http_method == 'PUT':
    import pychap

    for username, group in users:
      chap_user = pychap.authenticate(lambda x:x, username=username)
      store.putBaseUser(**{
        'username':username,
        'groups':['users', group],
        'nonce':chap_user.nonce,
        'nextnonce':chap_user.nextnonce})

    store.putBaseUser(**{
      'username': 'BASE_USER',
      'groups':['users'],
      'nonce':chap_user.nonce,
      'nextnonce':chap_user.nextnonce})

  if http_method == 'DELETE':
    for username, group in users:
      store.deleteBaseUser(username)

  respond('204 No Content','')


if __name__ == '__main__':
  main()
