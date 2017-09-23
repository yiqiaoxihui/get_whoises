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

mutex=threading.Lock()

def whois_query(begin,end):
	count=0
	left_ip=[]
	print "query"+str(begin)+'~'+str(end)+"start!"
	for i in range(begin-1,end):
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
		data=re.sub("\n{3,}","\n\n",data)
		data=re.sub(" {2,}", " ", data)
		data=data.strip()							#delete whitespace in head or tail
		data=data.replace("\n","\\n")
		if len(data)==0 or data=="Query rate limit exceeded":
			print str(begin)+'~'+str(end)+":"+"append to left_ip:"+ip_list[i]+"count:"+str(count)
			count=count+1
			left_ip.append(ip_list[i])
			continue
		if "'" in data:
			data='{"content":"'+data+'","ip":"'+ip_list[i]+'"}'
		else:
			data="{'content':'"+data+"','ip':'"+ip_list[i]+"'}"
		if mutex.acquire(True):
			w_fp.write(data)
			w_fp.write('\n')
			#w_fp.flush()
			mutex.release()
	#deal the left ip which is limit query
	while len(left_ip)>0:
		print str(begin)+'~'+str(end)+":"+"last left:"+str(len(left_ip))+"current ip:"+left_ip[0]
		arg = 'whois '+left_ip[0]
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
		#print data	
		if len(data)==0 or data=="Query rate limit exceeded":
			#print str(begin)+'~'+str(end)+":left_ip query fail"+"current ip:"+left_ip[0]
			left_ip.append(left_ip[0])
			del left_ip[0]
			continue
		if "'" in data:
			data='{"content":"'+data+'","ip":"'+left_ip[0]+'"}'
		else:
			data="{'content':'"+data+"','ip':'"+left_ip[0]+"'}"
		if mutex.acquire(True):
			w_fp.write(data)
			w_fp.write('\n')
			#w_fp.flush()
			mutex.release()
		del left_ip[0]
	#v_fp.close()
	print "query"+str(begin)+'~'+str(end)+"completed!"

def main():
	if __name__=='__main__':
		thread_count=10
		i=0
		data=""
		global ip_list,w_fp
		#global ip_list
		ip_fp=open('/data/all_neighbor_ip.txt','r')
		path="/data/whois_all_result_8724"
		w_fp=open(path,'w')
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
			ip_list[i]=ip_list[i].strip()
			#ip_list[i]=re.sub("\d*\/\d*","1",ip_list[i])
		ip_list=list(set(ip_list))
			#print ip_list[i]
		query_threads=[]
		#create multithread
		for i in range(0,thread_count):
			t = threading.Thread(target=whois_query,args=(parts[i][0],parts[i][1],))
			query_threads.append(t)
		#run multithread 
		for t in query_threads:
			t.setDaemon(False)		#
			t.start()
		for t in query_threads:
			t.join()
		w_fp.close()
		print "all query completed!"

		#for num in range(0,thread_count):
		#	print str(parts[num][0])+'~'+str(parts[num][1])
main()

