## -*- coding: utf-8 -*-
"""
Created on Thu July 30 17:42:49 2017

@author: ly
"""
import os
import re
#import requests
import json
import threading

data=""
path="/home/ly/get_whoises/whois_result_1"
#path1="/data/whois_result_view_"+str(begin)+'~'+str(end)
w_fp=open(path,'a')
#v_fp=open(path1,'a')
# data=w_fp.readline()
# data=eval(data)
# print data['content']
for i in range(0,1):
	arg = 'whois 115.20.0.1';
	query_result=os.popen(arg)
	data=""
	for line in query_result:
		if (line[0]=='%' or line[0]=='#'):    	#delete unnecessary info
			continue
		if(line[:6]=="route:"):
			break
		data=data+line
	#data=data.replace('\n\nroute:','\nroute:')
	#data=data.replace('\n\n\n\n','')
	#data=data.replace('\n\n\n','')
	data=re.sub("\n{3,}","\n\n",data)
	data=re.sub(" {2,}", " ", data)
	data=data.strip()							#delete whitespace in head or tail
	data=data.replace("\n","\\n")
	#print data	
	data="{'content': '"+data+"'}"
	result={}
	#result['ip']=ip_list[i]
	result['content']=data
	result=json.dumps(result)
	w_fp.write(data)
	#w_fp.write(data)
	w_fp.write('\n')
	#v_ip="ip:"+ip_list[i]
	#v_content="content:\n"+data
	#v_fp.write(v_ip)
	#v_fp.write(v_content)
	#v_fp.write('\n\n')
w_fp.close()
v_fp.close()
