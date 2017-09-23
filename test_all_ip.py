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

conn=MongoClient('127.0.0.1',27017)
db=conn.ly
my_mongo=db.whois1

a=0
b=0
whois_list=[]
hash_dic={}
#print my_mongo.count()
whois_fp=open('/data/all_ip.txt','r')#/home/ly/Documents/all
whois_all_ip=open('/data/all_ip_left.txt',"w")
left_ip=[]
count=0
while True:
	ip = whois_fp.readline()
	if ip=="":
		break
	else:
		a=a+1
		ip=ip.strip()
		data={}
		ip_num=socket.ntohl(struct.unpack("I",socket.inet_aton(ip))[0])
		data=my_mongo.find_one({'ip_begin':{'$lte':ip_num},'ip_end':{'$gte':ip_num}})
		if data:
			b=b+1
			print b
		else:
			arg = 'whois '+ip;
			query_result=os.popen(arg)
			data=""
			for line in query_result:
				if (line[0]=='%' or line[0]=='#'):    	#delete unnecessary info
					continue
				if(line[:6]=="route:"):
					break
				data=data+line
			data=re.sub("\n{3,}","\n\n",data)
			data=re.sub(" {2,}", " ", data)
			data=data.strip()							#delete whitespace in head or tail
			data=data.replace("\n","\\n")
			if len(data)==0 or data=="Query rate limit exceeded":
				print "query limit"+str(count)
				count=count+1
				left_ip.append(ip)
				continue
			data="{'content': '"+data+"','ip': '"+ip+"'}"
			whois_all_ip.write(data)
			whois_all_ip.write('\n')
while len(left_ip)>0:
	print "last left:"+str(len(left_ip))+"current ip:"+left_ip[0]
	arg = 'whois '+left_ip[0]
	query_result=os.popen(arg)
	data=""
	for line in query_result:
		if (line[0]=='%' or line[0]=='#'):    	#delete unnecessary info
			continue
		if(line[:6]=="route:"):
			break
		data=data+line
	data=re.sub("\n{3,}","\n\n",data)
	data=re.sub(" {2,}", " ", data)
	data=data.strip()							#delete whitespace in head or tail
	data=data.replace("\n","\\n")
	#print data	
	if len(data)==0 or data=="Query rate limit exceeded":
		left_ip.append(left_ip[0])
		del left_ip[0]
		continue
	data="{'content': '"+data+"','ip': '"+left_ip[0]+"'}"
	whois_all_ip.write(data)	
	whois_all_ip.write('\n')
	del left_ip[0]
whois_fp.close()
whois_all_ip.close()
print "last:"
print a
print b