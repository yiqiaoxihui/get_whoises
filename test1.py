## -*- coding: utf-8 -*-
import re
import os
import socket
import struct
import hashlib
import time
from pymongo import MongoClient
'''
author:liuyang
date:2017/12/16 20:15
desrc:read the raw whois data,extract the beginip,endip and data,insert into mongodb
'''
global ip_assign_list,limit_server_list_record
ip_assign_list=[]
limit_server_list_record={}
def md5(str):
    import hashlib
    m = hashlib.md5()  
    m.update(str)
    return m.hexdigest()

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
#def is_real_ip_range(content,):

#deal the ip which like 1.01.02.03
def deal_abnormal_ip(ip_begin,ip_end):
	ip_begin_arr=ip_begin.split('.')
	ip_end_arr=ip_end.split('.')
	temp=[]
	for c in ip_begin_arr:
		c=str(int(c))
		temp.append(c)
	ip_begin='.'.join(temp)
	temp=[]
	for c in ip_end_arr:
		c=str(int(c))
		temp.append(c)
	ip_end='.'.join(temp)
	return ip_begin,ip_end

def ip_to_number(raw_ip_begin,raw_ip_end):
	#the ip may be not normal
	try:
		ip_begin_num=socket.ntohl(struct.unpack("I",socket.inet_aton(str(raw_ip_begin)))[0])
		ip_end_num=socket.ntohl(struct.unpack("I",socket.inet_aton(str(raw_ip_end)))[0])
	except Exception as e:
		ip_begin,ip_end=deal_abnormal_ip(raw_ip_begin,raw_ip_end)
		ip_begin_num=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_begin)))[0])
		ip_end_num=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_end)))[0])
	return ip_begin_num,ip_end_num
def whois_insert(ip_begin,ip_end,content,hash):
	global my_mongo
	content=content.decode("unicode_escape")
	my_mongo.insert({"ip_begin":ip_begin,"ip_end":ip_end,"content":content,"hash":hash})
#some raw whois data maybe include more accurate ip whois info,
#this function can find the most accurate ip whois info
def get_accurate_whois_info(raw_content):
	useful_object_list=[
		r'inetnum {0,1}: {0,1}\d{1,3}\.\d{1,3}',
		r'NetRange {0,1}: {0,1}\d{1,3}\.\d{1,3}',
		r'Network Number {0,}\] {0,1}\d{1,3}\.\d{1,3}',
		r'IPv4 Address {0,}: {0,1}\d{1,3}\.\d{1,3}'
	]
	use_content=""
	object_item_list=raw_content.split("\n\n")
	for object_item in object_item_list:
		for useful_object in useful_object_list:
			ip_range=re.findall(useful_object,object_item)
			if len(ip_range)>0:
				#print "count:"+str(len(ip_range))+":"+ip_range[0]
				use_content=raw_content[raw_content.find(object_item):]

	use_content=use_content.strip()
	return use_content
def do_query(ip,server="",port=""):
	if server!="":
		arg="whois -h "+server+ " -p " +port +" "+ip
	else:
		arg="whois "+ip
	print arg
	query_result=os.popen(arg)
	data=""
	for line in query_result:
		if (line[0]=='%' or line[0]=='#'):    	#delete unnecessary info
			continue
		data=data+line
	data=re.sub("\n{3,}","\n\n",data)
	data=re.sub(" {2,}", " ", data)
	data=data.strip()							#delete whitespace in head or tail
	data=data.replace("\n","\\n")
	return data
def main():
	global limit_server_list_record,ip_assign_list
	server="whois.ripe.net"
	ip="5.4.4.4"
	ipn,ip1=ip_to_number(ip,'0.0.0.0')
	print ipn
	f=open('ip_del.h','r')
	ip_assigns_raw=f.readlines()
	
	f.close()
	for ip_a in ip_assigns_raw:
		ip_a=ip_a.strip()
		ip_a=ip_a.split(",")
		if ip_a==[]:
			continue
		ip_a[0]=int(ip_a[0])
		ip_a[1]=int(ip_a[1])
		ip_assign_list.append(ip_a)
	for ip_a in ip_assign_list:
		if((ipn&ip_a[1])==ip_a[0]):
			print "guest server:"+ip_a[2]
			server=ip_a[2]
			break

	if server=="whois.ripe.net":
		data=do_query(ip,server="localhost",port="8888")
		#query no
		if data.find("no entries found")>0 or len(data)==0:
			#互斥锁
			if limit_server_list_record.has_key(server):
				if time.time()-limit_server_list_record[server]>86400:
					del limit_server_list_record[server]
					print "push to queue:"+ip
					#print thread_name+":"+"limit append to queue:"+thread_ip_list[i]
					#ip_push_into_queue(thread_ip_list[i])
			#end 互斥锁
			else:
				data=do_query(ip)
				#data is null
				if len(data)==0 or data=="Query rate limit exceeded" or data.find("access from your host has been permanently")>0:
					#push to queue
					#print thread_name+":"+"limit append to queue:"+thread_ip_list[i]
					#ip_push_into_queue(thread_ip_list[i])
					print "push to queue:"+ip
					#互斥锁
					if limit_server_list_record.has_key(server):
						pass
					else:
						limit_server_list_record[server]=time.time()
					#end 互斥锁
					#continue
				#data is not null
				if '"' in data:
					data=data.replace('"','\\"')
				data='{"content":"'+data+'","ip":"'+ip+'","timestamp":"'+str(int(time.time()))+'"}'
		else:
			print "data:"+str(len(data))
			if '"' in data:
				data=data.replace('"','\\"')
			data='{"content":"'+data+'","ip":"'+ip+'","timestamp":"'+str(int(time.time()))+'"}'
	else:
		#server not ripe
		#互斥锁
		if limit_server_list_record.has_key(server):
			if time.time()-limit_server_list_record[server]>86400:
				del limit_server_list_record[server]
				print "push to queue:"+ip
				#print thread_name+":"+"limit append to queue:"+thread_ip_list[i]
				#ip_push_into_queue(thread_ip_list[i])
		#end 互斥锁
		else:
			data=do_query(ip)
			#data is null
			if len(data)==0 or data=="Query rate limit exceeded" or data.find("access from your host has been permanently")>0:
				#push to queue
				print "push to queue:"+ip
				#print thread_name+":"+"limit append to queue:"+thread_ip_list[i]
				#ip_push_into_queue(thread_ip_list[i])
				#互斥锁
				if limit_server_list_record.has_key(server):
					pass
				else:
					limit_server_list_record[server]=time.time()
				#end 互斥锁
				#continue
			#data is not null
			if '"' in data:
				data=data.replace('"','\\"')
			data='{"content":"'+data+'","ip":"'+ip+'","timestamp":"'+str(int(time.time()))+'"}'
	print data
	print limit_server_list_record
	#no limit
	#print int(ip_assign_list[10][0])
	#print ip_assign_list
main()



	




