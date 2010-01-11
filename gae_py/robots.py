"""This is just a handler script that returns an http response to a request for
robots.txt. The url that activates this script is configured in app.yaml
"""
def main():
  body = 'User-agent: *\nDisallow: /'
  print 'Status: 200 OK' 
  print 'Content-Type: text/plain'
  print 'Content-Length: %d' % len(body)
  # todo: use datetime to set an expires header in the future
  print 'Expires: -1'
  print 'Cache-Control: public'
  print
  print body 

if __name__ == '__main__':
  main()
