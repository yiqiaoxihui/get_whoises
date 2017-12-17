import socket
import struct
f=open('/data/all_ip_80w','r')
ip_list=f.readlines()
f.close()
print len(ip_list)
ff=open('/data/test1','w')
for item in ip_list:
	ff.write(item)
ff.close()
f1=open('/data/all_ip_80w','w')
f1.close()