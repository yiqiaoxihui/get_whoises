# import re
# import os
# import socket
# import struct
# import hashlib
# import json
# import collections
# from pymongo import MongoClient


# left_ip=[]
# def md5(str):
#     import hashlib
#     m = hashlib.md5()  
#     m.update(str)
#     return m.hexdigest()
# def get_useful_info_from_content(content):

# 	object_item_list=content.split("\n\n")
# 	#choose the main object
# 	useful_object_list=['inetnum','NetRange','Network Number','IPv4 Address']
# 	for object_item in object_item_list:
# 		for useful_object in useful_object_list:
# 			if useful_object in object_item:
# 				print object_item
# 		#if((object_item.find("")!=-1) or (object_item.find("")!=-1) or (object_item.find("")!=-1)or (object_item.find("")!=-1)):
			
# 	#if main_content=="":
# 		#print ip+": "+content
# 	# if main_content_array_k_v["whois"].has_key("descr") and len(main_content_array_k_v["whois"]["descr"])==0:
# 	# 	main_content_array_k_v["whois"].pop("descr")
# 	# if main_content_array_k_v["whois"].has_key("remarks") and len(main_content_array_k_v["whois"]["remarks"])==0:
# 	# 	main_content_array_k_v["whois"].pop("remarks")
# 	# if main_content_array_k_v["whois"].has_key("Comment") and len(main_content_array_k_v["whois"]["Comment"])==0:
# 	# 	main_content_array_k_v["whois"].pop("Comment")
# 		# attr_item=object_attr.split(":")
# 		# if(len(attr_item)!=2):
# 		# 	#print object_attr
# 		# 	continue
# 		# if(attr_item[0]=="descr"):
# 		# 	descr_list.append(attr_item[1])
# 		# elif(attr_item[0]=="remarks"):
# 		# 	remarks_list.append(attr_item[1])
# 		# else:
# 		# 	main_content_array_k_v["whois"][attr_item[0]]=attr_item[1]

# def deal_abnormal_ip(ip_begin,ip_end):
# 	ip_begin_arr=ip_begin.split('.')
# 	ip_end_arr=ip_end.split('.')
# 	temp=[]
# 	for c in ip_begin_arr:
# 		c=str(int(c))
# 		temp.append(c)
# 	ip_begin='.'.join(temp)
# 	temp=[]
# 	for c in ip_end_arr:
# 		c=str(int(c))
# 		temp.append(c)
# 	ip_end='.'.join(temp)
# 	return ip_begin,ip_end

# def ip_to_number(raw_ip_begin,raw_ip_end):
# 	try:
# 		ip_begin_num=socket.ntohl(struct.unpack("I",socket.inet_aton(str(raw_ip_begin)))[0])
# 		ip_end_num=socket.ntohl(struct.unpack("I",socket.inet_aton(str(raw_ip_end)))[0])
# 	except Exception as e:
# 		ip_begin,ip_end=deal_abnormal_ip(raw_ip_begin,raw_ip_end)
# 		ip_begin_num=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_begin)))[0])
# 		ip_end_num=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_end)))[0])
# 	return ip_begin_num,ip_end_num
# conn=MongoClient('127.0.0.1',27017)
# db=conn.ly
# my_mongo=db.whois1

# whois_list=[]
# json_list=[]
# json_count=0
# #print my_mongo.count()
# whois_filepath=raw_input("please input whois file path:")
# write2json_filepath=raw_input("please input write to json path:")
# if whois_filepath=='':
# 	whois_filepath="/data/all"
# if write2json_filepath=='':
# 	write2json_filepath='/data/test2'

# whois_fp=open(whois_filepath,'r')#/home/ly/Documents/all
# fpw=open(write2json_filepath,"w")

# while True:
# 	raw_content = whois_fp.readline()
# 	if raw_content=="":
# 		break
# 	else:
# 		dic_content=eval(raw_content)
# 		content=dic_content['content']
# 		object_item_list=content.split("\n\n")
# 		#choose the main object
# 		flag=0
# 		temp=""
# 		useful_object_list=[r'inetnum {0,}: {0,1}\d{1,3}\.\d{1,3}',r'NetRange {0,1}: {0,1}\d{1,3}\.\d{1,3}',r'Network Number {0,}\] {0,1}\d{1,3}\.\d{1,3}',r'IPv4 Address {0,}: {0,1}\d{1,3}\.\d{1,3}']
# 		for object_item in object_item_list:
# 			for useful_object in useful_object_list:
# 				ip_range=re.findall(useful_object,object_item)
# 				if len(ip_range)>0:
# 					flag=1
# 					#print "count:"+str(len(ip_range))+":"+ip_range[0]
# 					temp=content[content.find(object_item):]
# 		# if content1!="":
# 		# 	fpw.write(content1)
# 		# 	fpw.write("\n************************************************\n")
# 		content=temp
# 		ip_range=re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", content)
# 		#print content
# 		#print ip_range
# 		if ip_range!=[]:
# 			ip_range_str=str(ip_range[0][0])+str(ip_range[0][1])
# 			#print ip_range[0]
# 			#ip->number
# 			print str(ip_range[0][0])+'~'+str(ip_range[0][1])
# 			ip_begin,ip_end=ip_to_number(ip_range[0][0],ip_range[0][1])
# 			print str(ip_begin)+'~'+str(ip_end)
# 		# if flag==0 and len(content)!=0:
# 		# 	fpw.write(content)
# 		# 	fpw.write("\n************************************************\n")
# 		# object_item_list=content1.split("\n")
# 		# useful_object_list=['inetnum','NetRange','Network Number','IPv4 Address']
# 		# for object_item in object_item_list:
# 		# 	for useful_object in useful_object_list:
# 		# 		if useful_object in object_item:
# 		# 			print object_item
# 		# 			fpw.write(object_item)
# 		# 			fpw.write("\n")
# 		# 			break
# 		# 	break


# whois_fp.close()
# fpw.close()


# print "json_count:"
# print json_count


# # conn=MongoClient('127.0.0.1',27017)
# # db=conn.ly
# # my_mongo=db.whois

# # hash_dic={}
# # rows=my_mongo.find({},{'hash':1})
# # for row in rows:
# # 	hash_dic[row['hash']]=1
# # def md5(str):
# #     import hashlib
# #     m = hashlib.md5()  
# #     m.update(str)
# #     return m.hexdigest()
# # print len(md5('df'))
# # content='NetRange: 140.224.0.0 - 140.224.255.255\nCIDR: 140.224.0.0/16\nNetName: APNIC-ERX-140-224-0-0\nNetHandle: NET-140-224-0-0-1\nParent: NET140 (NET-140-0-0-0-0)\nNetType: Early Registrations, Transferred to APNIC\nOriginAS: \nOrganization: Asia Pacific Network Information Centre (APNIC)\nRegDate: 2010-11-03\nUpdated: 2010-11-17\nComment: This IP address range is not registered in the ARIN database.\nComment: This range was transferred to the APNIC Whois Database as\nComment: part of the ERX (Early Registration Transfer) project.\nComment: For details, refer to the APNIC Whois Database via\nComment: WHOIS.APNIC.NET or http://wq.apnic.net/apnic-bin/whois.pl\nComment: \nComment: ** IMPORTANT NOTE: APNIC is the Regional Internet Registry\nComment: for the Asia Pacific region. APNIC does not operate networks\nComment: using this IP address range and is not able to investigate\nComment: spam or abuse reports relating to these addresses. For more\nComment: help, refer to http://www.apnic.net/apnic-info/whois_search2/abuse-and-spamming\nRef: https://whois.arin.net/rest/net/NET-140-224-0-0-1\n\nResourceLink: http://wq.apnic.net/whois-search/static/search.html\nResourceLink: whois.apnic.net\n\nOrgName: Asia Pacific Network Information Centre\nOrgId: APNIC\nAddress: PO Box 3646\nCity: South Brisbane\nStateProv: QLD\nPostalCode: 4101\nCountry: AU\nRegDate: \nUpdated: 2012-01-24\nRef: https://whois.arin.net/rest/org/APNIC\n\nReferralServer: whois://whois.apnic.net\nResourceLink: http://wq.apnic.net/whois-search/static/search.html\n\nOrgTechHandle: AWC12-ARIN\nOrgTechName: APNIC Whois Contact\nOrgTechPhone: +61 7 3858 3188 \nOrgTechEmail: search-apnic-not-arin@apnic.net\nOrgTechRef: https://whois.arin.net/rest/poc/AWC12-ARIN\n\nOrgAbuseHandle: AWC12-ARIN\nOrgAbuseName: APNIC Whois Contact\nOrgAbusePhone: +61 7 3858 3188 \nOrgAbuseEmail: search-apnic-not-arin@apnic.net\nOrgAbuseRef: https://whois.arin.net/rest/poc/AWC12-ARIN\n\nFound a referral to whois.apnic.net.\n\ninetnum: 140.224.0.0 - 140.224.127.255\nnetname: CHINANET-FJ\ndescr: CHINANET FUJIAN NETWORK\ncountry: CN\nadmin-c: CA67-AP\ntech-c: CA67-AP\nstatus: ALLOCATED NON-PORTABLE\nmnt-by: MAINT-CHINANET-FJ\nmnt-lower: MAINT-CHINANET-FJ\nmnt-routes: MAINT-CHINANET-FJ\nmnt-irt: IRT-CHINANET-FJ\nchanged: zhengzm@gsta.com 20130128\nsource: APNIC\n\nirt: IRT-CHINANET-FJ\naddress: no.7,dongjie road,fuzhou,fujian,china\ne-mail: fjnic@fjdcb.fz.fj.cn\nabuse-mailbox: abuse@fjdcb.fz.fj.cn\nadmin-c: CA67-AP\ntech-c: CA67-AP\nauth: # Filtered\nmnt-by: MAINT-CHINANET-FJ\nchanged: fjnic@fjdcb.fz.fj.cn 20101206\nsource: APNIC\n\nrole: CHINANETFJ IP ADMIN\naddress: 7,East Street,Fuzhou,Fujian,PRC\ncountry: CN\nphone: +86-591-83309761\nfax-no: +86-591-83371954\ne-mail: fjnic@fjdcb.fz.fj.cn\nremarks: send spam reports and abuse reports\nremarks: to abuse@fjdcb.fz.fj.cn\nremarks: Please include detailed information and\nremarks: times in UTC\nadmin-c: FH71-AP\ntech-c: FH71-AP\nnic-hdl: CA67-AP\nremarks: www.fjtelecom.com\nnotify: fjnic@fjdcb.fz.fj.cn\nmnt-by: MAINT-CHINANET-FJ\nchanged: fjnic@fjdcb.fz.fj.cn 20100108\nsource: APNIC\nchanged: hm-changed@apnic.net 20111114'
# # position=content.find('Found a referral to')
# # position=content.find('inetnum',position)
# # content=content[position:]
# # ip_range=re.findall(r"{0,}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", content)
# # print ip_range

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
	print raw_ip_begin+"~"+raw_ip_end
	try:
		ip_begin_num=socket.ntohl(struct.unpack("I",socket.inet_aton(str(raw_ip_begin)))[0])
		ip_end_num=socket.ntohl(struct.unpack("I",socket.inet_aton(str(raw_ip_end)))[0])
	except Exception as e:
		ip_begin,ip_end=deal_abnormal_ip(raw_ip_begin,raw_ip_end)
		print ip_begin+"~"+ip_end
		ip_begin_num=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_begin)))[0])
		ip_end_num=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_end)))[0])
	return ip_begin_num,ip_end_num
def whois_insert(ip_begin,ip_end,content,hash):
	content=content.decode("unicode_escape")
	my_mongo.insert({"ip_begin":ip_begin,"ip_end":ip_end,"content":content,"hash":hash})

conn=MongoClient('127.0.0.1',27017)
db=conn.ly
my_mongo=db.whois3
repeat=0
use=0
s=0
undeal=0
noquery=0
whois_list=[]
hash_dic={}
dic={}
path=raw_input("please input the file path:")
if path=='':
	path="/data/all"
whois_fp=open(path,'r')#/home/ly/Documents/all
#read hash for no repeat data
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
		object_item_list=raw_content.split("\n\n")
		useful_object_list=[r'inetnum {0,1}: {0,1}\d{1,3}\.\d{1,3}',r'NetRange {0,1}: {0,1}\d{1,3}\.\d{1,3}',r'Network Number {0,}\] {0,1}\d{1,3}\.\d{1,3}',r'IPv4 Address {0,}: {0,1}\d{1,3}\.\d{1,3}']
		for object_item in object_item_list:
			for useful_object in useful_object_list:
				ip_range=re.findall(useful_object,object_item)
				if len(ip_range)>0:
					#print "count:"+str(len(ip_range))+":"+ip_range[0]
					use_content=raw_content[raw_content.find(object_item):]

		use_content=use_content.strip()
		if use_content=='':
			undeal=undeal+1
			continue

		#(\d+.\d+.\d+.\d+) - (\d+.\d+.\d+.\d+)
		#x.x.x.x/n
		#x.x.x/n
		#x.x/n
		ip_range_regs=[
		r'((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:[1-9][0-9]\.)|(?:[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:[1-9][0-9])|(?:[0-9]))) {0,1}- {0,1}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:[1-9][0-9]\.)|(?:[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:[1-9][0-9])|(?:[0-9])))',
		r'((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:[1-9][0-9]\.)|(?:[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:[1-9][0-9])|(?:[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])',
		r'((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:[1-9][0-9]\.)|(?:[0-9]\.)){2}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:[1-9][0-9])|(?:[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])',
		r'((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:[1-9][0-9]\.)|(?:[0-9]\.)){1}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:[1-9][0-9])|(?:[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])']
		#for ip_range_reg in ip_range_regs:
		ip_range=re.findall(ip_range_regs[2],use_content)
		if ip_range!=[]:
			if ip_range_regs.index(ip_range_regs[2])>0:
				print ip_range
				ip_begin,ip_end=ip_n_to_ip(ip_range[0])
			else:
				ip_begin=ip_range[0][0]
				ip_end=ip_range[0][1]
			str_ip=str(ip_begin)+'~'+str(ip_end)
			#print str_ip
			ip_begin_num,ip_end_num=ip_to_number(ip_begin,ip_end)
			ip_range_str=str(ip_begin_num)+str(ip_end_num)
			hash=md5(ip_range_str)#skip the same ip range
			if hash_dic.has_key(hash):
				#print line
				dic[str_ip]=dic[str_ip]+1
				repeat=repeat+1
				#break
			else:
				print "**********************\n\n"
				print use_content
				use=use+1
				hash_dic[hash]=1
				dic[str_ip]=1
			#whois_insert(ip_begin_num,ip_end_num,use_content,hash)
		#break

print "repeat:"+str(repeat)
print "insert:"+str(use)
print "undeal:"+str(undeal)
print "no content:"+str(noquery)
print "sum:"+str(s)