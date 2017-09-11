import re
import os
import socket
import struct
import hashlib

def ip_n_to_ip(ip_num):
	#192.1.2.3/20
	print ip_num
	i=ip_num[0].count('.')
	if i==1:
		ip=ip_num[0]+'.0.0'
	elif i==2:
		ip=ip_num[0]+'.0'
	elif i==0:
		ip=ip_num[0]+'.0.0.0'
	else:
		ip=ip_num[0]
	print ip
	if int(ip_num[1])<32 and int(ip_num[1])>0:
		#print ip_num[1]
		ip_begin=""
		ip_end=""
		ip_int=int(ip_num[1])/8
		ip_rem=int(ip_num[1])%8
		elements=ip.split('.')
		for i in range(0,ip_int):
			ip_begin=ip_begin+elements[i]+'.'
			ip_end=ip_end+elements[i]+'.'
			print ip_begin
			print ip_end
		ip_begin=ip_begin+str(int(elements[ip_int])&(~((1<<(8-ip_rem))-1)))
		ip_end=ip_end+str(int(elements[ip_int])|((1<<(8-ip_rem))-1))
		if ip_int<3:
			for i in range(ip_int+1,4):
				ip_begin=ip_begin+'.'+'0'
				ip_end=ip_end+'.'+'255'
		return ip_begin,ip_end
	elif int(ip_num[1])==32:
		return ip,ip
	else:
		return '0.0.0.0','0.0.0.0'
ip=[('0.0', '32'), ('177.82.160.0', '20')]

ip_begin,ip_end=ip_n_to_ip(ip[0])
print ip_begin+'~'+ip_end