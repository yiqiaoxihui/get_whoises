import re
import os
import socket
import struct
import hashlib
from pymongo import MongoClient



def md5(str):
    import hashlib
    m = hashlib.md5()  
    m.update(str)
    return m.hexdigest()
def ip_n_to_ip(ip):
	#192.1.2.3/20
	ip_begin=""
	ip_end=""
	ip_int=ip[1]/8
	ip_rem=ip[1]%8
	elements=ip[0].split('.')
	for i in range(0,ip_int):
		ip_begin=ip_begin+elements[i]+'.'
		ip_end=ip_end+elements[i]+'.'
	ip_begin=ip_begin+str(int(elements[ip_int])&(1<(8-ip_rem)))
	ip_end=ip_end+str(int(elements[ip_int])|((1<(8-ip_rem))-1))
	if ip_int<3:
		for i in range(ip_int+1,4):
			ip_begin=ip_begin+'.'+'0'
			ip_end=ip_end+'.'+'255'
	return ip_begin,ip_end
def ip_n_to_ip(ip_num):
	#192.1.2.3/20
	#print ip_num
	i=ip_num[0].count('.')
	if i==1:
		ip=ip_num[0]+'.0.0'
	elif i==2:
		ip=ip_num[0]+'.0'
	elif i==0:
		ip=ip_num[0]+'.0.0.0'
	else:
		ip=ip_num[0]
	#print ip
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
			#print ip_begin
			#print ip_end
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

conn=MongoClient('127.0.0.1',27017)
db=conn.ly
my_mongo=db.whois
repeat=0
use=0
s=0
undeal=0
noquery=0
whois_list=[]
hash_dic={}
whois_fp=open('/data/whois_result_1~89848','r')#/home/ly/Documents/all
while True:
    line = whois_fp.readline()
    if line=="":
        break
    else:
		s=s+1
		dic=eval(line)
		content=dic['content']#(\d+.\d+.\d+.\d+) - (\d+.\d+.\d+.\d+)

		#get x.x.x.x - x.x.x.x
		ip_range=re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", content)
		#print content
		#print ip_range
		if ip_range!=[]:
			hash=md5(content)#skip the same content
			if hash_dic.has_key(hash):
				#print line
				repeat=repeat+1
				continue
			else:
				use=use+1
				hash_dic[hash]=1
			#print ip_range[0]
			#ip->number
			ip_begin=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_range[0][0])))[0])
			ip_end=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_range[0][1])))[0])
			print str(ip_range[0][0])+'~'+str(ip_range[0][1])
			
			#print hash
			content=content.decode("unicode_escape")
			my_mongo.insert({"ip_begin":ip_begin,"ip_end":ip_end,"content":content,"hash":hash})
		else:
			ip_range=re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})",content)
			#x.x.x.x/n
			if ip_range!=[]:
				hash=md5(content)#skip the same content
				if hash_dic.has_key(hash):
					repeat=repeat+1
					continue
				else:
					use=use+1
					hash_dic[hash]=1
				ip_begin,ip_end=ip_n_to_ip(ip_range[0])
				#print ip_range
				print str(ip_begin)+'~'+str(ip_end)
				ip_begin=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_begin)))[0])
				ip_end=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_end)))[0])
				content=content.decode("unicode_escape")
				my_mongo.insert({"ip_begin":ip_begin,"ip_end":ip_end,"content":content,"hash":hash})
			else:
				ip_range=re.findall(r"inetnum:(\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})",content)
				#x.x.x/n
				if ip_range!=[]:
					hash=md5(content)#skip the same content
					if hash_dic.has_key(hash):
						repeat=repeat+1
						continue
					else:
						use=use+1
						hash_dic[hash]=1
					ip_begin,ip_end=ip_n_to_ip(ip_range[0])
					#print ip_range
					print str(ip_begin)+'~'+str(ip_end)
					ip_begin=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_begin)))[0])
					ip_end=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_end)))[0])
					content=content.decode("unicode_escape")
					my_mongo.insert({"ip_begin":ip_begin,"ip_end":ip_end,"content":content,"hash":hash})
				else:
					ip_range=re.findall(r"inetnum:(\d{1,3}\.\d{1,3})\/(\d{1,2})",content)
					#x.x/n
					if ip_range!=[]:
						hash=md5(content)#skip the same content
						if hash_dic.has_key(hash):
							repeat=repeat+1
							continue
						else:
							use=use+1
							hash_dic[hash]=1
						ip_begin,ip_end=ip_n_to_ip(ip_range[0])
						#print ip_range
						print str(ip_begin)+'~'+str(ip_end)
						ip_begin=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_begin)))[0])
						ip_end=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_end)))[0])
						content=content.decode("unicode_escape")
						my_mongo.insert({"ip_begin":ip_begin,"ip_end":ip_end,"content":content,"hash":hash})
					elif len(content)>0 and content!="Query rate limit exceeded":
						#print line
						undeal=undeal+1
					else:
						noquery=noquery+1

print repeat
print use
print undeal
print noquery
print s
#	while content.find("NetRange:",1)>0 or content.find("inetnum:",1)>0:
#		if content.find("NetRange:",1)>0:
#			len1=content.find("NetRange:",1)
#		else:
#			len1=content.find("inetnum",1)
#		list.append(content[0:len1])
#		content=content[len1:]
#	list.append(content)
#for line in list:
#	print line
#	print '**********************'



	




