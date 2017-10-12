import re
import os
import socket
import struct
import hashlib
import json
import collections
from pymongo import MongoClient


left_ip=[]
def md5(str):
    import hashlib
    m = hashlib.md5()  
    m.update(str)
    return m.hexdigest()
def get_useful_info_from_content(ip,content):
	main_content_array_k_v=collections.OrderedDict()
	main_content_array_k_v["IP_addr"]=ip
	main_content_array_k_v["whois"]=collections.OrderedDict()
	object_item_list=[]
	main_content=""
	object_item_list=content.split("\n\n")
	#choose the main object
	useful_object_list=['inetnum','NetRange','Network Number','IPv4 Address']
	for object_item in object_item_list:
		for useful_object in useful_object_list:
			if useful_object in object_item:
				main_content=object_item
	object_attrs=main_content.split("\n")
	attr_item=[]
	i=0
	dns=collections.OrderedDict()


	#useful=['inetnum','NetRange','descr','CIDR','NetName','Organization','Updated','NetType']
	all_key=[
	'NetRange','CIDR','NetName','NetHandle','Parent','NetType','OriginAS','Organization','RegDate','Updated','Comment','Ref',
	'inetnum','aut-num','abuse-c','owner','ownerid','responsible','address',
	'netname','descr','country','geoloc','language','org','sponsoring-org','admin-c',
	'phone','owner-c','tech-c','status','remarks','notify','mnt-by','mnt-lower','mnt-routes','mnt-domains','mnt-irt',
	'inetrev','dns',
	'Network Number','Network Name','Administrative Contact','Technical Contact','Nameserver','Assigned Date','Return Date','Last Update',
	'IPv4 Address','Organization Name','Network Type','Address','Zip Code','Registration Date'
	'created','last-modified','changed','source','parent'
	]

	RIPE=['inetnum','netname','descr','country','geoloc','language','org','sponsoring-org','admin-c','tech-c','status',
	'remarks','notify','mnt-by','mnt-lower','mnt-routes','mnt-domains','mnt-irt','created','last-modified','source']

	APNIC=['inetnum','netname','descr','country','geoloc','language','admin-c','tech-c','status',
	'remarks','notify','mnt-by','mnt-lower','mnt-routes','mnt-irt','changed','source']

	ARIN=['NetRange','CIDR','NetName','NetHandle','Parent','NetType','OriginAS','Organization','RegDate','Updated','Comment','Ref']

	LACNIC=['inetnum','aut-num','abuse-c','owner','ownerid','responsible','address','country',
	'phone','owner-c','tech-c','status','inetrev','nserver','nsstat','nslastaa','created','changed']

	AFRINIC=['inetnum','netname','descr','country','org','admin-c','tech-c','status','remarks','notify',
	'mnt-by','mnt-lower','mnt-routes','mnt-domains','mnt-irt','source','parent']

	JPNIC=['Network Number','Network Name','Administrative Contact','Technical Contact','Nameserver','Assigned Date','Return Date','Last Update']

	KRNIC=['IPv4 Address','Organization Name','Network Type','Address','Zip Code','Registration Date']

	dns_list=['nserver','nsstat','nslastaa']
	array_key=['descr','remarks','Comment','mnt-by','mnt-lower','mnt-routes','mnt-domains','changed','dns']
	org_list=['org','Organization','Organization Name']
	#main_content_array_k_v["whois"]["remarks"]=[]
	#main_content_array_k_v["whois"]["dns"]=[]
	for object_attr in object_attrs:
		for key in all_key:
			position=object_attr.find(key)
			if position>=0 and position<=7:
				if object_attr[(position+len(key)):].strip()[0:1]!=":" and object_attr[(position+len(key)):].strip()[0:1]!="]":
					continue
				value=object_attr[position+len(key):].strip()
				#value_position=position+len(key)+1 #+1 for : or ]
				value=value[1:].strip()
				if key in array_key:
					if main_content_array_k_v["whois"].has_key(key):
						main_content_array_k_v["whois"][key].append(value)
					else:
						main_content_array_k_v["whois"][key]=[]
						main_content_array_k_v["whois"][key].append(value)
				elif key in dns_list:
					if main_content_array_k_v["whois"].has_key('dns'):
						dns[key]=value
						if len(dns.keys())>=3:
							main_content_array_k_v["whois"]['dns'].append(dns)
							dns=collections.OrderedDict()
					else:
						main_content_array_k_v["whois"]['dns']=[]
						dns[key]=value
				else:
					main_content_array_k_v["whois"][key]=value
				break
	exist_key=set(main_content_array_k_v["whois"].keys()) & set(array_key)
	for key in exist_key:
		if len(main_content_array_k_v["whois"][key])==0:
			main_content_array_k_v["whois"].pop(key)
	# if main_content_array_k_v["whois"].has_key("descr") and len(main_content_array_k_v["whois"]["descr"])==0:
	# 	main_content_array_k_v["whois"].pop("descr")
	# if main_content_array_k_v["whois"].has_key("remarks") and len(main_content_array_k_v["whois"]["remarks"])==0:
	# 	main_content_array_k_v["whois"].pop("remarks")
	# if main_content_array_k_v["whois"].has_key("Comment") and len(main_content_array_k_v["whois"]["Comment"])==0:
	# 	main_content_array_k_v["whois"].pop("Comment")
		# attr_item=object_attr.split(":")
		# if(len(attr_item)!=2):
		# 	#print object_attr
		# 	continue
		# if(attr_item[0]=="descr"):
		# 	descr_list.append(attr_item[1])
		# elif(attr_item[0]=="remarks"):
		# 	remarks_list.append(attr_item[1])
		# else:
		# 	main_content_array_k_v["whois"][attr_item[0]]=attr_item[1]

	date1="20170901-09:13:00"
	main_content_array_k_v["whois"]["timestamp"]=date1
	jsonStr= json.dumps(main_content_array_k_v)
	#print jsonStr
	#print "\n"
	return main_content_array_k_v

conn=MongoClient('127.0.0.1',27017)
db=conn.ly
my_mongo=db.whois1

whois_list=[]
json_list=[]
json_count=0
#print my_mongo.count()
whois_filepath=raw_input("please input whois file path:")
write2json_filepath=raw_input("please input write to json path:")
if whois_filepath=='':
	whois_filepath="/data/whois_all_result_8724_left"
if write2json_filepath=='':
	write2json_filepath='/data/write_to_json.json'

whois_fp=open(whois_filepath,'r')#/home/ly/Documents/all
# fpw=open(write2json_filepath,"w")
# fpw.write("[")
while True:
	raw_content = whois_fp.readline()
	if raw_content=="":
		break
	else:
		dic_content=eval(raw_content)
		ip=dic_content['ip']
		content=dic_content['content']
		m=re.match("^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$",ip)
		if not m:
			print "error ip type:"+str(m)
			continue
		jsonStr=get_useful_info_from_content(ip,content)
		json_list.append(jsonStr)
		json_count=json_count+1
		#if(json_count>=10000)
		# fpw.write(jsonStr)
		# fpw.write(",\n")
# fpw.seek(-2,2)
with open(write2json_filepath,'w') as json_file:
	json.dump(json_list,json_file,indent=4)


whois_fp.close()
#fpw.close()


print "json_count:"
print json_count