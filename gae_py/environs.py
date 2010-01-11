"""environs.py is a request handler script that simply prints a list of
contents of the os.environ set by App Engine and sends it as an http message
back to the caller.  This is designed to act as a handler for a url directive
in app.yaml.
"""
import os

print 'Status: 200 OK' 
print 'Content-Type: text/plain'
print 'expires: -1'
print

for name in os.environ.keys():
  print '%s : %s\n' % (name, os.environ.get(name))
