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
end_thread_signal=0
ip_list=[]
w_fp=0
wl_fp=0
def whois_query(begin,end):
	#global end_thread_signal,w_fp,wl_fp,ip_list
	count=0
	left_ip=[]
	print "query"+str(begin)+'~'+str(end)+"start!"
	for i in range(begin-1,end):
		if(end_thread_signal==1):
			print str(begin)+'~'+str(end)+":stop!"
			for j in range(i,end):
				if mutex.acquire(True):
					wl_fp.write(ip_list[j])
					wl_fp.write('\n')
					#w_fp.flush()
					mutex.release()
			break
		print str(begin)+'~'+str(end)+":"+str(i)+'ip:'+ip_list[i]
		arg = 'whois '+ip_list[i];
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
		if(end_thread_signal==1):
			for line in left_ip:
				if mutex.acquire(True):
					wl_fp.write(line)
					wl_fp.write('\n')
					#w_fp.flush()
					mutex.release()
			break
		else:
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

	print "query"+str(begin)+'~'+str(end)+"completed!"
def listen_key():
	global end_thread_signal
	while(True):
		print "linsten_key:"
		key=raw_input()
		print "key:"+key
		if 'stop' in key:
			end_thread_signal=1
			print "end_thread_signal:"+str(end_thread_signal)
			break
		if end_thread_signal==2:
			break

def main():
	if __name__=='__main__':
		#end_thread_signal=0
		thread_count=10
		i=0
		global ip_list,w_fp,wl_fp,end_thread_signal
		#global ip_list
		end_thread_signal=0
		ip_path=raw_input("please input ip file path:")
		ip_in_row=input("please input the row of ip of the file(0~N):")
		result_path=raw_input("please input result path:")
		ip_left_path=raw_input("please input ip left path:")
		thread_count=input("please input the thread number:")
		result_path="/data/whois_all_result_8724"
		ip_path='/data/all_neighbor_ip.txt'
		ip_left_path='/data/8724_left'
		ip_in_row=0
		ip_fp=open(ip_path,'r')
		wl_fp=open(ip_left_path,'a')
		w_fp=open(result_path,'a')
		ip_list=ip_fp.readlines()
		ip_fp.close()
		ip_count=len(ip_list)
		print ip_count
		ip_list=list(set(ip_list))
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
			ip_list[i]=ip_list[i].split()[ip_in_row]
			ip_list[i]=ip_list[i].strip()
			#ip_list[i]=re.sub("\d*\/\d*","1",ip_list[i])
			print ip_list[i]
		print len(ip_list)
		query_threads=[]
		#create multithread
		for i in range(0,thread_count):
			t = threading.Thread(target=whois_query,args=(parts[i][0],parts[i][1],))
			query_threads.append(t)
		#run multithread 
		for t in query_threads:
			t.setDaemon(False)		#
			t.start()
		threading.Thread(target=listen_key).start()
		for t in query_threads:
			t.join()
		w_fp.close()
		wl_fp.close
		print "all query completed!"
		end_thread_signal=2
		print len(ip_list)
		#for num in range(0,thread_count):
		#	print str(parts[num][0])+'~'+str(parts[num][1])
main()

