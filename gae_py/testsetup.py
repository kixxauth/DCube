"""Set up the sys-admin, user-admin, account-admin, and database level test
users for remote automated testing.
"""
#######################################################################
#
#   Do not fuck with with this handler! (it is a big security issue)  #
#
#######################################################################

import os

_DONE = False

def respond(status, body):
  print 'Status: %s'% status
  print 'Content-Type: text/plain'
  print 'Content-Length: %d' % len(body)
  print 'Expires: -1'
  print 'Cache-Control: private'
  print
  print body 

def main():
  global _DONE

  # Check to see if we are on the local dev_appserver.
  # If not, we bail!
  if not os.environ['SERVER_SOFTWARE'].startswith('Development'):
    respond('403 Forbidden','')
    return

  # Short circuit if we have already been setup
  if _DONE:
    respond('204 No Content','')
    return

  # This is the only handler script where we should ever see this import.
  import store
  import pychap

  users = [
        ('test_sys_admin', 'sys_admin'),
        ('test_user_admin', 'user_admin'),
        ('test_account_admin', 'account_admin'),
        ('test_database_admin', 'database')
      ]

  def putuser(user):
    pass

  for username, group in users:
    chap_user = pychap.authenticate(lambda x:x, username=username)
    user = store.getBaseUser(username)
    user.username = username
    user.nonce = chap_user.nonce
    user.nextnonce = chap_user.nextnonce
    user.groups = ['users', group]
    store.putBaseUser(**user.__dict__)

  respond('204 No Content','')
  _DONE = True

if __name__ == '__main__':
  main()
