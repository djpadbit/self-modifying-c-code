import sys,socket,struct

if len(sys.argv) < 2:
	print "Usage : %s <ip>" % sys.argv[0]
	print "Example : %s 192.168.1.24" % sys.argv[0]
	exit(0)
	
h = socket.inet_aton(sys.argv[1])
print "IP       : %s" % sys.argv[1]
print "Dec      : %i" % struct.unpack("!I",h)[0]
print "Hex      : %s" % hex(struct.unpack("!I",h)[0])
print 'Char arr : "\\x%s"' % '\\x'.join(x.encode('hex') for x in h)