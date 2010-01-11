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
import os
import yaml
import logging

import factory

# todo: What are the performance and App Engine instance boot up implications
# of loading a file at module load time like this?
groups = yaml.load(
    open(
      os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'groups.yaml')))
# todo: Should the 'groups' global be private?

def get_builder(username, permissions, interface):
  """Takes a username, group membership list, and interface name and returns
  the named builder function from the factory module if and only if there is a
  group listing for the interface in groups.yaml, the interface factory exists
  in the factory module, and the given group has permission on the given
  interface as determined by groups.yaml.
  """
  g = groups.get(interface)
  if g is None:
    logging.warn(('gate.get_builder(): '
      'There is no groups config for interface "%s".'), interface)
    return None
  for p in permissions:
    if p in g:
      builder = getattr(factory, interface, None)
      if builder is None:
        logging.warn(('gate.get_builder(): '
          'There is no builder for interface "%s".'), interface)
        return None
      return builder(username, permissions)

  logging.warn(('gate.get_builder(): '
    'permission denied for interface "%s".'), interface)
  return None
