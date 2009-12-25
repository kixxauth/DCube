def main():
  body = 'User-agent: *\nDisallow: /'
  print 'Status: 200 OK' 
  print 'Content-Type: text/plain'
  print 'Content-Length: %d' % len(body)
  print 'expires: -1'
  print
  print body 

if __name__ == '__main__':
  main()
