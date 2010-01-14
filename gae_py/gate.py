"""This module is the "gatekeeper" to the datastore.

One of the design goals of our program is to provide limited access to data in
the datastore based on a "Unix like" permissions system of users and user
groups. The foundation for this design is to limit the possibility of
programmer errors that could result in exposing more of the datastore than what
is intended.

The design is implemented by first loading a groups configuration file (groups.yaml)
into the global 'groups' and then whenever get_builder() is called it returns the named
builder function from the factory module provided the specified conditions are met.
"""
import groups
import logging

import factory

# todo: Should the 'groups' global be private?
groups = groups.map

def get_builder(username, user_groups, interface):
  """Check user capabilities and build an datastore interface function.

  Takes a username, group membership list, and interface name and returns the
  named builder function from the factory module if and only if 3 conditions
  are met:
  
  1. There is a group listing for the interface in groups.yaml. 
  2. The interface factory exists in the factory module. 
  3. The given group has permission on the given interface as determined by
  groups.yaml.
  
  Args:
    username: User name string.
    user_groups: List of groups the user belongs to.
    interface: Datastore interface to build.

  Returns:
    An interface function if all the conditions are met, or None if not.
  """
  builder = None
  level = 0

  for g in user_groups:
    group = groups.get(g)
    if group is None:
      logging.warn('gate.get_builder(): There is no group config for "%s".', g)
      return None

    if group['level'] > level:
      level = group['level']

    if interface in group['interfaces']:
      builder = getattr(factory, interface, None)
      if builder is None:
        logging.warn(('gate.get_builder(): '
          'There is no builder for interface "%s".'), interface)
        return None

  if callable(builder):
    return builder(username, level)

  logging.warn(('gate.get_builder(): '
    'permission denied for interface "%s".'), interface)
  return None

