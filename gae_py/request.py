url_mapping = []

def main():
  found = False
  for regex, handler in url_mapping:
    match = regex.match()
    if match:
      found = True
      handler(match.groups())
      break

  if not found:
    print 'Status: 404 Not Found' 
    print 'Content-Type: text/plain'

if __name__ == '__main__':
  main()
