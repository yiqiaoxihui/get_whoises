import socket
import struct
f=open('../liuyang','w')
f.write('sdf%s' % '123')
f.write('asd')
f.close()
number=(10<<24)+(255<<2)+2
str1='r010_123'
print "aaaaaa"+str(str1.find('dr010_'))
#print socket.inet_ntoa(struct.pack('!L', number))
def test():
	global a
	a=1

	def in_test():
		global a
		a=a+1
	in_test()
	print a
test()