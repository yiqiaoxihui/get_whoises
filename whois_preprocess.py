#-*-coding:utf-8 -*-
import re
import os
import socket
import struct
import hashlib
from pymongo import MongoClient
'''
author:liuyang
date:2017/12/16 20:15
desrc:read the raw whois data,extract the beginip,endip and data,insert into mongodb
'''
def whois_insert(ip_begin,ip_end,content,hash):
	global my_mongo
	if my_mongo.find({'hash':hash}).count()<=0:
		#将unicode内存编码值直接存储
		content=content.decode("unicode_escape")
		my_mongo.insert({"ip_begin":ip_begin,"ip_end":ip_end,"content":content,"hash":hash})
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
def main():
	conn=MongoClient('127.0.0.1',27017)
	db=conn.ly
	global my_mongo
	my_mongo=db.whois3
	repeat=0
	use=0
	s=0
	undeal=0
	noquery=0
	whois_list=[]
	hash_dic={}
	dic={}
	deal_fail_fp=open("/data/test2",'w')#/home/ly/Documents/all
	path=raw_input("please input the file path:")
	if path=='':
		path='/data/whois_raw'
	whois_fp=open(path,'r')#/home/ly/Documents/all
	#read hash for no repeat data
	#attentation:hash by begin_ip_number+end_ip_number
	rows=my_mongo.find({},{'hash':1})
	for row in rows:
		hash_dic[row['hash']]=1
	while True:
	    line = whois_fp.readline()
	    if line=="":
	        break
	    else:
			s=s+1
			whois_dic=eval(line)
			raw_content=whois_dic['content']
			#ip=dic['ip']
			#for referral info
			# position=content.find('Found a referral to')
			# if position>0:
			# 	position=content.find('inetnum',position)
			# 	if position>0:
			# 		content=content[position:]
			#TODO no concern ipv6
			if raw_content=='':
				noquery=noquery+1
				continue
			use_content=""
			use_content=get_accurate_whois_info(raw_content)
			if use_content=='':
				undeal=undeal+1
				continue

			#the netrange reg rule:
			#(\d+.\d+.\d+.\d+) - (\d+.\d+.\d+.\d+)
			#x.x.x.x/n
			#x.x.x/n
			#x.x/n
			ip_range_regs=[
			r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9]))) {0,1}- {0,1}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))',
			r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])',
			r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){2}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])',
			r'(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){1}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])'
			]
			flag=0
			for ip_range_reg in ip_range_regs:
				ip_range=re.findall(ip_range_reg,use_content)
				if ip_range!=[]:
					flag=1
					if ip_range_regs.index(ip_range_reg)>0:
						ip_begin,ip_end=ip_n_to_ip(ip_range[0])
					else:
						ip_begin=ip_range[0][0]
						ip_end=ip_range[0][1]
					str_ip=str(ip_begin)+'~'+str(ip_end)
					print str_ip
					ip_begin_num,ip_end_num=ip_to_number(ip_begin,ip_end)
					ip_range_str=str(ip_begin_num)+str(ip_end_num)
					hash=md5(ip_range_str)#skip the same ip range
					if hash_dic.has_key(hash):
						#print line
						#dic[str_ip]=dic[str_ip]+1
						repeat=repeat+1
						break
					else:
						use=use+1
						hash_dic[hash]=1
						#dic[str_ip]=1
						whois_insert(ip_begin_num,ip_end_num,use_content,hash)
						break
				
			if flag==0:
				#can not find ip range in this whois raw data
				deal_fail_fp.write(use_content)
				deal_fail_fp.write('\n**************************\n')

		#break
	deal_fail_fp.close()
	# dic= sorted(dic.items(), key=lambda d:d[1], reverse = True)
	# repeat1=0
	# for item in dic:
	# 	if item[1]>1:
	# 		repeat1=repeat1+item[1]-1
	# 	deal_fail_fp.write(item[0]+":"+str(item[1])+"\n")
	# deal_fail_fp.close()
	print "repeat:"+str(repeat)
	print "insert:"+str(use)
	print "undeal:"+str(undeal)
	print "no content:"+str(noquery)
	print "sum:"+str(s)
main()
		# ip_range=re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", content)
		# #print content
		# #print ip_range
		# if ip_range!=[]:
		# 	ip_range_str=str(ip_range[0][0])+str(ip_range[0][1])
		# 	hash=md5(ip_range_str)#skip the same ip range
		# 	if hash_dic.has_key(hash):
		# 		#print line
		# 		repeat=repeat+1
		# 		continue
		# 	else:
		# 		use=use+1
		# 		hash_dic[hash]=1

		# 	print str(ip_range[0][0])+'~'+str(ip_range[0][1])
		# 	ip_begin,ip_end=ip_to_number(ip_range[0][0],ip_range[0][1])
		# 	#print str(ip_range[0][0])+'~'+str(ip_range[0][1])
		# 	whois_insert(ip_begin,ip_end,content,hash)

		# else:
		# 	ip_range=re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})",content)
		# 	#x.x.x.x/n
		# 	if ip_range!=[]:
		# 		ip_begin,ip_end=ip_n_to_ip(ip_range[0])
		# 		ip_range_str=ip_begin+ip_end
		# 		hash=md5(ip_range_str)#skip the same ip range
		# 		if hash_dic.has_key(hash):
		# 			repeat=repeat+1
		# 			continue
		# 		else:
		# 			use=use+1
		# 			hash_dic[hash]=1
		# 		ip_begin,ip_end=ip_to_number(ip_begin,ip_end)
		# 		#print str(ip_range[0][0])+'~'+str(ip_range[0][1])
		# 		whois_insert(ip_begin,ip_end,content,hash)
		# 	else:
		# 		ip_range=re.findall(r"inetnum:(\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})",content)
		# 		#x.x.x/n
		# 		if ip_range!=[]:
		# 			ip_begin,ip_end=ip_n_to_ip(ip_range[0])
		# 			ip_range_str=ip_begin+ip_end
		# 			hash=md5(ip_range_str)#skip the same ip range
		# 			if hash_dic.has_key(hash):
		# 				repeat=repeat+1
		# 				continue
		# 			else:
		# 				use=use+1
		# 				hash_dic[hash]=1
		# 			ip_begin,ip_end=ip_to_number(ip_begin,ip_end)
		# 			#print str(ip_range[0][0])+'~'+str(ip_range[0][1])
		# 			whois_insert(ip_begin,ip_end,content,hash)
		# 		else:
		# 			ip_range=re.findall(r"inetnum:(\d{1,3}\.\d{1,3})\/(\d{1,2})",content)
		# 			#x.x/n
		# 			if ip_range!=[]:
		# 				ip_begin,ip_end=ip_n_to_ip(ip_range[0])
		# 				ip_range_str=ip_begin+ip_end
		# 				hash=md5(ip_range_str)#skip the same ip range
		# 				if hash_dic.has_key(hash):
		# 					repeat=repeat+1
		# 					continue
		# 				else:
		# 					use=use+1
		# 					hash_dic[hash]=1
		# 				ip_begin,ip_end=ip_to_number(ip_begin,ip_end)
		# 				#print str(ip_range[0][0])+'~'+str(ip_range[0][1])
		# 				whois_insert(ip_begin,ip_end,content,hash)
		# 			elif len(content)>0 and content!="Query rate limit exceeded":
		# 				print " content:"+content
		# 				undeal=undeal+1
		# 			else:
		# 				#print content
		# 				noquery=noquery+1


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



	




