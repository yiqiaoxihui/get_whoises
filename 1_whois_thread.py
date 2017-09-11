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

def whois_query(begin,end):
	print "query"+str(begin)+'~'+str(end)+"start!"
	print ip_list[0]
	data=""
	path="/data/whois_result_"+str(begin)+'~'+str(end)
	#path1="/data/whois_result_view_"+str(begin)+'~'+str(end)
	w_fp=open(path,'a')
	#v_fp=open(path1,'a')

	for i in range(begin,end+1):
		print str(begin)+'~'+str(end)+":"+str(i)+'ip:'+ip_list[i]
		arg = 'whois '+ip_list[i];
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
		#print data	
		result={}
		#result['ip']=ip_list[i]
		result['content']=data
		w_fp.write(str(result))
		#w_fp.write(data)
		w_fp.write('\n')
		#v_ip="ip:"+ip_list[i]
		#v_content="content:\n"+data
		#v_fp.write(v_ip)
		#v_fp.write(v_content)
		#v_fp.write('\n\n')
	w_fp.close()
	#v_fp.close()
	print "query"+str(begin)+'~'+str(end)+"completed!"

thread_count=10
i=0
data=""
ip_fp=open('/data/20170706.origins','r')
ip_list=ip_fp.readlines()
ip_fp.close()
ip_count=len(ip_list)
print ip_count
current=0
part= ip_count / thread_count
parts=[[] for i in range(thread_count)]
#create ip segement for multithread
for num in range(0,thread_count):
	if num<thread_count-1:
		parts[num].append(current+1)
		current=current+part
		parts[num].append(current)
	else:
		parts[num].append(current+1)
		parts[num].append(ip_count)
#preprocessing ip
for i in range(0,ip_count):
	ip_list[i]=ip_list[i].split()[0]
	ip_list[i]=re.sub("\d*\/\d*","1",ip_list[i])
	
	#print ip_list[i]
query_threads=[]
#create multithread
for i in range(0,thread_count):
	t = threading.Thread(target=whois_query,args=(parts[i][0],parts[i][1],))
	query_threads.append(t)
#run multithread 
for t in query_threads:
	t.setDaemon(False)			#
	t.start()
t.join()
print "all query completed!"

#for num in range(0,thread_count):
#	print str(parts[num][0])+'~'+str(parts[num][1])




