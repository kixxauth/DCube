"""
A list of datastore interfaces and the groups that have permission on each one.
Used by the gate and factory modules (gate.py)
"""

map = {

    'users': {'level': 0, 'interfaces': [
      'create_new_user',
      'update_public_user',
      'get_public_user',
      'delete_user']},

    'database': {'level': 60, 'interfaces': [
      ]},

    'account_admin': {'level': 70, 'interfaces': [
      ]},

    'user_admin': {'level': 80, 'interfaces': [
      ]},

    'sys_admin': {'level': 90, 'interfaces': [
      ]},

    'ROOT': {'level': 100, 'interfaces': [
      'get_chap_user_creds',
      'get_user_groups',
      'update_chap_user_creds']}
    }
