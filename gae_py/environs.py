import os

print 'Status: 200 OK' 
print 'Content-Type: text/plain'
print 'expires: -1'
print

for name in os.environ.keys():
  print '%s : %s\n' % (name, os.environ.get(name))
