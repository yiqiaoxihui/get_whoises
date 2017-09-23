import re
import os
import socket
import struct
import hashlib
import json
from pymongo import MongoClient



def md5(str):
    import hashlib
    m = hashlib.md5()  
    m.update(str)
    return m.hexdigest()
def get_useful_info_from_content(ip,content):
	main_content_array_k_v={}
	main_content_array_k_v[ip]={}
	main_content_array_k_v[ip]["whois"]={}
	object_items=[]
	main_content=""
	object_items=content.split("\n\n")
	for object_item in object_items:
		if((object_item.find("NetRange")!=-1) or (object_item.find("inetnum")!=-1)):
			main_content=object_item

	object_attrs=main_content.split("\n")
	attr_item=[]
	i=0
	descr_list=[]
	useful=['inetnum','NetRange','descr','CIDR','NetName','Organization','Updated','NetType']
	for object_attr in object_attrs:
		attr_item=object_attr.split(":")
		if(len(attr_item)<2):
			continue
		if(attr_item[0]=="descr"):
			descr_list.append(attr_item[1])
		else:
			main_content_array_k_v[ip]["whois"][attr_item[0]]=attr_item[1]
	main_content_array_k_v[ip]["whois"]["descr"]=descr_list
	date1="20170901-23:13:00"
	main_content_array_k_v[ip]["whois"]["timestamp"]=date1
	jsonStr= json.dumps(main_content_array_k_v)
	return jsonStr


conn=MongoClient('127.0.0.1',27017)
db=conn.ly
my_mongo=db.whois1

a=0
b=0
whois_list=[]
#print my_mongo.count()
whois_fp=open('/data/all_ip.txt','r')#/home/ly/Documents/all
fpw=open('/data/write_to_json.txt',"w")
left_ip=[]
count=0
while True:
	ip = whois_fp.readline()
	if ip=="":
		break
	else:
		a=a+1
		ip=ip.strip()
		main_content_array_k_v={}
		main_content_array_k_v[ip]={}
		main_content_array_k_v[ip]["whois"]={}
		m=re.match("^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$",ip)
		if not m:
			print "error ip type:"+str(m)
			# jsonStr=json.dumps(main_content_array_k_v)
			# fpw.write(jsonStr)
			# fpw.write('\n')
			continue
		#print "ip:"+ip
		ip_num=socket.ntohl(struct.unpack("I",socket.inet_aton(ip))[0])
		#print ip_num
		rows=my_mongo.find({'ip_begin':{'$lte':ip_num},'ip_end':{'$gte':ip_num}})
		#count1=my_mongo.find({'ip_begin':{'$lte':0},'ip_end':{'$gte':ip_num}}).count()
		#break
		#print a
		result={}
		last_distance=4294967295
		result['ip_begin']=0
		result['ip_end']=4294967295
		result['content']=""
		rows_count=0
		print "bid db,ip:"+"count:"+str(a)
		for row in rows:
			rows_count=rows_count+1
			#print "bid db,ip:"+ip+"rows:"+str(rows_count)
			if (row['ip_end']-row['ip_begin'])<last_distance:
				#choose the most accurate one
				last_distance=row['ip_end']-row['ip_begin']
				result['ip_begin']=row['ip_begin']
				result['ip_end']=row['ip_end']
				result['content']=row['content']
				#print result
			ips=re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", row['content'])
			if len(ips)>1:
				ip_begin=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ips[len(ips)-1][0])))[0])
				ip_end=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ips[len(ips)-1][1])))[0])
				if(ip_num>=ip_begin and ip_num<=ip_end):
					#choose the most accurate one
					if((ip_end-ip_begin)<last_distance):
						second=1
						ip_range=ips[len(ips)-1][0]
						last_distance=ip_end-ip_begin
						result['ip_begin']=row['ip_begin']
						result['ip_end']=row['ip_end']
						result['content']=row['content']
			#other type of ip segement
			#TODO
		if(result['content']!=""):		
			jsonStr=get_useful_info_from_content(ip,result['content'])
			fpw.write(jsonStr)
			fpw.write("\n")
			b=b+1
		else:
			print "online query:"+ip
			arg = 'whois '+ip
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
			json=get_useful_info_from_content(ip,data)
			fpw.write(data)
			fpw.write('\n')
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
	jsonStr=get_useful_info_from_content(left_ip[0],data)
	fpw.write(jsonStr)
	fpw.write('\n')
	del left_ip[0]
whois_fp.close()
fpw.close()


print "last:"
print a
print b