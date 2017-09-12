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
	#print ip_list[0]
	data=""
	path_repeat="/data/repeat/whois_result_left_repeat_"+str(begin)+'~'+str(end)
	path_left="/data/left/whois_result_left_"+str(begin)+'~'+str(end)
	#path1="/data/whois_result_view_"+str(begin)+'~'+str(end)
	r_fp=open(path_repeat,'a')
	l_fp=open(path_left,'r')
	#v_fp=open(path1,'a')
	count=0;
	left_ip=[]
	line_num=0
	while True:
		line=l_fp.readline()
		if line=="":
			break
		else:
			line_num=line_num+1
			dic=eval(line)
			content=dic['content']
			if len(content)==0 or content=="Query rate limit exceeded":
				print str(begin)+'~'+str(end)+":"+"repeat query"+"current line:"+str(line_num)
				arg = 'whois '+dic['ip'];
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
				data=re.sub(" {2,}", "", data)
				data=data.strip()							#delete whitespace in head or tail
				#print data	
				if len(data)==0 or data=="Query rate limit exceeded":
					print str(begin)+'~'+str(end)+":"+"append to left_ip:"+dic['ip']+"count:"+str(count)
					count=count+1
					left_ip.append(dic['ip'])
					continue
				result={}
				#result['ip']=ip_list[i]
				result['content']=data
				result['ip']=dic['ip']
				r_fp.write(str(result))
				r_fp.write('\n')
			else:
				print str(begin)+'~'+str(end)+":"+"normal"
				r_fp.write(line)
				#r_fp.write('\n')
	#deal no find
	while len(left_ip)>0:
		print str(begin)+'~'+str(end)+":"+"left:"+len(left_ip)+"current ip:"+left_ip[0]
		arg = 'whois '+left_ip[0];
		query_result=os.popen(arg)
		data=""
		for line in query_result:
			if (line[0]=='%' or line[0]=='#'):    	#delete unnecessary info
				continue
			if(line[:6]=="route:"):
				break
			data=data+line
		data=re.sub("\n{3,}","\n\n",data)
		data=re.sub(" {2,}", "", data)
		data=data.strip()							#delete whitespace in head or tail
		#print data	
		if len(data)==0 or data=="Query rate limit exceeded":
			print str(begin)+'~'+str(end)+":left_ip query fail"+"current ip:"+left_ip[0]
			lefp_ip.append(left_ip[0])
			del lefp_ip[0]
			continue
		result={}
		#result['ip']=ip_list[i]
		result['content']=data
		result['ip']=left_ip[0]
		r_fp.write(str(result))
		#w_fp.write(data)
		r_fp.write('\n')
		del left_ip[0]
	l_fp.close()
	r_fp.close()
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




