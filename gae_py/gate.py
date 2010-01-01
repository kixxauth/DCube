import os
import yaml
import logging

import factory

groups = yaml.load(
    open(
      os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'groups.yaml')))

def get_builder(username, permissions, interface):
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
