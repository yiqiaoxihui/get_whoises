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
	#print "query"+str(begin)+'~'+str(end)+"start!"
	path_left_left_1="/data/repeat/left2/left2_result/whois_result_left_left_1_"+str(begin)+'~'+str(end)
	path_left_left="/data/repeat/left2/whois_result_left_left_"+str(begin)+'~'+str(end)
	ll_fp=open(path_left_left,'r')
	#ll1_fp=open(path_left_left_1,'a')
	left_ip=[]
	while True:
		line=ll_fp.readline()
		if line=="":
			break
		else:
			dic=eval(line)
			left_ip.append(dic['ip'])
	#left_ip=set(left_ip)
	print  "query"+str(begin)+'~'+str(end)+"count:"+str(len(left_ip))
	# for line in left_ip:
	# 	result={}
	# 	#result['ip']=ip_list[i]
	# 	result['content']=""
	# 	result['ip']=line
	# 	ll_fp.write(str(result))
	# 	#w_fp.write(data)
	# 	ll_fp.write('\n')
	# ll_fp.close()
	# while len(left_ip)>0:
	# 	print str(begin)+'~'+str(end)+":"+"last left:"+str(len(left_ip))+"current ip:"+left_ip[0]
	# 	arg = 'whois '+left_ip[0]
	# 	query_result=os.popen(arg)
	# 	data=""
	# 	for line in query_result:
	# 		if (line[0]=='%' or line[0]=='#'):    	#delete unnecessary info
	# 			continue
	# 		if(line[:6]=="route:"):
	# 			break
	# 		data=data+line
	# 	data=re.sub("\n{3,}","\n\n",data)
	# 	data=re.sub(" {2,}", "", data)
	# 	data=data.strip()							#delete whitespace in head or tail
	# 	#print data	
	# 	if len(data)==0 or data=="Query rate limit exceeded":
	# 		#print str(begin)+'~'+str(end)+":left_ip query fail"+"current ip:"+left_ip[0]
	# 		left_ip.append(left_ip[0])
	# 		del left_ip[0]
	# 		continue
	# 	result={}
	# 	#result['ip']=ip_list[i]
	# 	result['content']=data
	# 	result['ip']=left_ip[0]
	# 	ll1_fp.write(str(result))
	# 	#w_fp.write(data)
	# 	ll1_fp.write('\n')
	# 	del left_ip[0]
	# ll1_fp.close()
	# print "query"+str(begin)+'~'+str(end)+"completed!"

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




