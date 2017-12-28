## -*- coding: utf-8 -*-
"""
Created on Thu sep 24 17:42:49 2017

@author: ly
@descrp:this file run linux whois command to get whois data by the given the ip list of file
"""
import os
import re
#import requests
import json
import threading
import socket
import struct
import hashlib
import time
from pymongo import MongoClient

write_result_lock=threading.Lock()
write_left_ip_lock=threading.Lock()
ip_list_lock=threading.Lock()
limit_server_lock=threading.Lock()
write_db_lock=threading.Lock()
break_thread_signal=0
ip_list=[]
ip_number_hash_dic={}
wr_fp=0
wl_fp=0
fetch_count=5
ip_assign_list=[]
#[server,]
limit_server_list_record={}
def fetch_from_queue(thread_name):
	global ip_list,ip_list_lock
	list=[]
	if ip_list_lock.acquire():
		print thread_name+"begin fetch_ip,ip_list count:"+str(len(ip_list))
		if(len(ip_list)>fetch_count):
			list=ip_list[0:fetch_count]
			ip_list=ip_list[fetch_count:]
		else:
			list=ip_list
			ip_list=[]
		print thread_name+"end fetch_ip,ip_list count:"+str(len(ip_list))
		ip_list_lock.release()
	return list
def ip_push_into_queue(ip):
	global ip_list,ip_list_lock
	if ip_list_lock.acquire():
		ip_list.append(ip)
		ip_list_lock.release()

def ip_n_to_ip_list(ipn):
	list=[]
	ip_num=re.findall(r"(.+)\/(\d{1,2})",ipn)
	if len(ip_num)<=0:
		list.append(ipn)
		return list
	#don't deal ipv6
	if ipn.find(":")>=0:
		return list
	#print ip_num[0][0]
	i=ip_num[0][0].count('.')
	ip=ip_num[0][0]
	if i!=3:	
		if i==1:
			ip=ip_num[0][0]+'.0.0'
		elif i==2:
			ip=ip_num[0][0]+'.0'
		elif i==0:
			ip=ip_num[0][0]+'.0.0.0'
		else:
			ip=ip_num[0][0]
	#print ip
	if int(ip_num[0][1])<32 and int(ip_num[0][1])>0:
		#print ip_num[1]
		ip_begin=""
		ip_end=""
		ip_int=int(ip_num[0][1])/8
		ip_rem=int(ip_num[0][1])%8
		elements=ip.split('.')
		for i in range(0,ip_int):
			ip_begin=ip_begin+elements[i]+'.'
			ip_end=ip_end+elements[i]+'.'
		ip_begin=ip_begin+str(int(elements[ip_int])&(~((1<<(8-ip_rem))-1)))
		ip_end=ip_end+str(int(elements[ip_int])|((1<<(8-ip_rem))-1))
		#print ip_begin+"~"+ip_end
		if ip_int<3:
			for i in range(ip_int+1,4):
				ip_begin=ip_begin+'.'+'0'
				ip_end=ip_end+'.'+'255'
				#print ip_begin+"~"+ip_end
		ip_begin=ip_begin.split('.')
		ip_end=ip_end.split('.')
		for ip_0 in range(int(ip_begin[0]),int(ip_begin[0])+1):
			for ip_1 in range(int(ip_begin[1]),int(ip_end[1])+1):
				for ip_2 in range(int(ip_begin[2]),int(ip_end[2])+1):
					list.append(str(ip_0)+'.'+str(ip_1)+'.'+str(ip_2)+'.1')
		return list
	elif int(ip_num[0][1])==32:
		list.append(ip)
		return list
	else:
		return list

def ip_n_list_to_ip_list(ipn_list):
	l=[]
	for ipn in ipn_list:
		list=ip_n_to_ip_list(ipn)
		for ip in list:
			#print ip
			l.append(ip)
	return l
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
def get_accurate_data_ip(use_content):
	global ip_number_hash_dic
	ip_range_regs=[
	r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9]))) {0,1}- {0,1}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))',
	r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])',
	r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){2}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])',
	r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){1}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])'
	]
	for ip_range_reg in ip_range_regs:
		ip_range=re.findall(ip_range_reg,use_content)
		if ip_range!=[]:
			if ip_range_regs.index(ip_range_reg)>0:
				ip_begin,ip_end=ip_n_to_ip(ip_range[0])
			else:
				ip_begin=ip_range[0][0]
				ip_end=ip_range[0][1]
			#str_ip=str(ip_begin)+'~'+str(ip_end)
			#print str_ip
			ip_begin_num,ip_end_num=ip_to_number(ip_begin,ip_end)
			ip_range_str=str(ip_begin_num)+str(ip_end_num)
			h=md5(ip_range_str)#skip the same ip range
			if ip_number_hash_dic.has_key(h):
				return 0,0,0,0
			else:
				ip_number_hash_dic[h]=1
				return 1,ip_begin_num,ip_end_num,h
	return 0,0,0,0
def whois_insert(ip_begin,ip_end,content,hash):
	global my_mongo
	if my_mongo.find({'hash':hash}).count()<=0:
		content=content.decode("unicode_escape")
		my_mongo.insert({"ip_begin":ip_begin,"ip_end":ip_end,"content":content,"hash":hash})
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
def md5(str):
    import hashlib
    m = hashlib.md5()  
    m.update(str)
    return m.hexdigest()
'''
Number of queries from an IP address – Unlimited [1]
xNumber of queries passed by a proxy – Unlimited [1]
xNumber of personal data sets returned in queries from an IP address –
1,000 per 24 hours [3]
xNumber of personal data sets returned in queries from a proxy IP
address – 20,000 per 24 hours [3] 
#inetnum:118.208.0.0 - 118.211.255.255 very frequence
'''
def whois_query(thread_name):
	global ip_assign_list,limit_server_list_record
	global break_thread_signal,wr_fp,wl_fp,ip_list
	global write_left_ip_lock,write_result_lock,limit_server_lock,write_db_lock

	while(len(ip_list)>0):
		if break_thread_signal==1:
			break
		ipn_list=fetch_from_queue(thread_name)
		thread_ip_list=ip_n_list_to_ip_list(ipn_list)
		count=0
		ip_count=len(thread_ip_list)
		for i in range(0,ip_count):
			if(break_thread_signal==1):
				print thread_name+" stop!"
				for j in range(i,ip_count):
					if write_left_ip_lock.acquire(True):
						wl_fp.write(thread_ip_list[j])
						wl_fp.write('\n')
						#wr_fp.flush()
						write_left_ip_lock.release()
				#the break must in this place,or will lost some ip
				break
			print thread_name+' current ip:'+thread_ip_list[i]
			server="whois.ripe.net"
			ip=thread_ip_list[i]
			ipn=socket.ntohl(struct.unpack("I",socket.inet_aton(ip))[0])
			for ip_a in ip_assign_list:
				if((ipn&ip_a[1])==ip_a[0]):
					print thread_name+" ip:"+ip+" guest server:"+ip_a[2]
					server=ip_a[2]
					break
			#time is arrive,remove limit
			#continue can not in mutex!!!dead mutex 
			limit_flag=0
			if limit_server_lock.acquire(True):
				if limit_server_list_record.has_key(server):
					limit_flag=1
					if time.time()-limit_server_list_record[server]>86400:
						del limit_server_list_record[server]
						print thread_name+" remove limite and push to queue,server:"+server+"ip:"+ip
						#print thread_name+":"+"limit append to queue:"+thread_ip_list[i]
						ip_push_into_queue(ip)
						#continue
					else:
						print thread_name+" left limite: "+str(86400-time.time()+limit_server_list_record[server])+"s and push to queue,server:"+server+"ip:"+ip
						#print thread_name+":"+"limit append to queue:"+thread_ip_list[i]
						ip_push_into_queue(ip)
						#continue
				limit_server_lock.release()
			if limit_flag==1:
				continue
			if server=="whois.ripe.net":
				print thread_name+" server:"+server+"query from local first"
				data=do_query(ip,server="10.10.11.130",port="8888")
				#query no
				if data.find("no entries found")>0 or len(data)==0:
					data=do_query(ip)
					#data is null
					if len(data)==0 or data=="Query rate limit exceeded" or data.find("access from your host has been permanently")>0:
						#push to queue
						print thread_name+" add limite and push to queue,server:"+server+" ip:"+ip
						ip_push_into_queue(thread_ip_list[i])
						#互斥锁
						if limit_server_lock.acquire(True):
							if limit_server_list_record.has_key(server):
								pass
							else:
								limit_server_list_record[server]=time.time()
							limit_server_lock.release()
						#end 互斥锁
						continue
					#data is not null
					if '"' in data:
						data=data.replace('"','\\"')
					data='{"content":"'+data+'","ip":"'+ip+'","timestamp":"'+str(int(time.time()))+'"}'
				else:
					if '"' in data:
						data=data.replace('"','\\"')
					data='{"content":"'+data+'","ip":"'+ip+'","timestamp":"'+str(int(time.time()))+'"}'
			#server is not ripe
			else:
				data=do_query(ip)
				#data is null
				if len(data)==0 or data=="Query rate limit exceeded" or data.find("access from your host has been permanently")>0:
					#push to queue
					print thread_name+" add limite and push to queue,server:"+server+" ip:"+ip
					ip_push_into_queue(thread_ip_list[i])
					#互斥锁
					if limit_server_lock.acquire(True):
						if limit_server_list_record.has_key(server):
							pass
						else:
							limit_server_list_record[server]=time.time()
						limit_server_lock.release()
					#end 互斥锁
					continue
				#data is not null
				if '"' in data:
					data=data.replace('"','\\"')
				#get int seconds
				data_dic='{"content":"'+data+'","ip":"'+ip+'","timestamp":"'+str(int(time.time()))+'"}'
			print "all left ip:"+str(len(ip_list))

			use_content=get_accurate_whois_info(data)
			flag,ip_begin_num,ip_end_num,h=get_accurate_data_ip(use_content)
			if flag==1:
				if write_result_lock.acquire(True):
					wr_fp.write(data_dic)
					wr_fp.write('\n')
					#wr_fp.flush()
					write_result_lock.release()
				if write_db_lock.acquire(True):
					whois_insert(ip_begin_num,ip_end_num,use_content,h)
					write_db_lock.release()

	print thread_name+" query completed!"

def break_keep():
	global break_thread_signal,write_left_ip_lock,ip_list_lock,wl_fp,ip_list
	while(True):
		print "linsten_key:"
		key=raw_input()
		print "key:"+key
		if 'stop' in key:
			if ip_list_lock.acquire(True):
				print "begin write ip_list:"+str(len(ip_list))
				if write_left_ip_lock.acquire(True):
					for ip in ip_list:
						wl_fp.write(ip)
						wl_fp.write('\n')
					write_left_ip_lock.release()
					ip_list_lock.release()
				print "begin write ip_list:"+str(len(ip_list))
				break_thread_signal=1
			print "break_thread_signal:"+str(break_thread_signal)
			break
		if break_thread_signal==2:
			break
#recover mode
#result file path:./query_whois_raw_dir/whois_query_result
#left ip file path:./query_whois_raw_dir/left_ip
#default all ip:./query_whois_raw_dir/all_ip

def recover():
	global ip_list,wr_fp,wl_fp
	recover_flag="n"
	result_path="./query_whois_raw_dir/whois_query_result"
	ip_left_path="./query_whois_raw_dir/left_ip"
	recover_flag=raw_input("do you want recover?(y/n,default n):")
	if os.path.exists("query_whois_raw_dir")==False:
		os.makedirs("query_whois_raw_dir")
		print "can not find query_whois_raw_dir dir,first run!"
		recover_flag=''
	if recover_flag=='':
		recover_flag='n'
	if recover_flag=='y':
		ip_in_row=0
		#ip_left_path=raw_input("please input the left ip path(recover mode):")
		#result_path=raw_input("please input the path to keep result(recover mode):")
		ip_fp=open(ip_left_path,'r')
		ip_list=ip_fp.readlines()
		ip_fp.close()
	else:
		ip_path=raw_input("please input ip file path:")
		#the ip file content like: ip    as    ...
		ip_in_row=raw_input("please input the row of ip in the file(0~N):")
		# result_path=raw_input("please input result path:")
		# ip_left_path=raw_input("please input ip left path:")
		#recover_path=raw_input("please input ip recover path:")
		if ip_path=='':
			ip_path='./all_ip'
		if ip_in_row=='':
			ip_in_row=0
		else:
			ip_in_row=int(ip_in_row)
		ip_fp=open(ip_path,'r')
		ip_list=ip_fp.readlines()
		ip_fp.close()
	ip_count=len(ip_list)
	for i in range(0,ip_count):
		ip_list[i]=ip_list[i].split()[ip_in_row]
		ip_list[i]=ip_list[i].strip()
		#ip_list[i]=re.sub("\d*\/\d*","1",ip_list[i])
		#print ip_list[i]
	ip_list=list(set(ip_list))
	ip_count=len(ip_list)
	print ip_count
	wl_fp=open(ip_left_path,'w')
	wr_fp=open(result_path,'a')

def init_ip_assign():
	global ip_assign_list
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
def main():
	conn=MongoClient('127.0.0.1',27017)
	db=conn.ly
	global my_mongo
	my_mongo=db.whois3
	#break_thread_signal=0
	i=0
	#break_thread_signal=0
	global ip_list,wr_fp,wl_fp,break_thread_signal,fetch_count
	recover()
	init_ip_assign()
	thread_count=raw_input("please input the thread number:")
	if thread_count=='':
		thread_count=10
	else:
		thread_count=int(thread_count)
	fetch_count=raw_input("please input the ip count fetch from queue for once:")
	if fetch_count=='':
		fetch_count=10
	else:
		fetch_count=int(fetch_count)


	query_threads=[]
	#create multithread
	for i in range(0,thread_count):
		t = threading.Thread(target=whois_query,args=("thread "+str(i),))
		query_threads.append(t)
	#run multithread 
	for t in query_threads:
		t.setDaemon(False)		#
		t.start()
	threading.Thread(target=break_keep).start()
	for t in query_threads:
		t.join()
	wr_fp.close()
	wl_fp.close
	print "all query completed!"
	break_thread_signal=2
	print len(ip_list)
	#for num in range(0,thread_count):
	#	print str(parts[num][0])+'~'+str(parts[num][1])
if __name__=='__main__':
	main()

