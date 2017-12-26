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

write_result_lock=threading.Lock()
write_left_ip_lock=threading.Lock()
ip_list_lock=threading.Lock()

break_thread_signal=0
ip_list=[]
wr_fp=0
wl_fp=0
fetch_count=5
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
	global break_thread_signal,wr_fp,wl_fp,ip_list,write_left_ip_lock,write_result_lock
	key_str="Found a referral to "
	limit_recode=0
	last_limit_flag=0
	query_limits_count=1000

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
			print thread_name+'current:'+thread_ip_list[i]
			arg = 'whois '+thread_ip_list[i];
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
			position=data.find(key_str)
			if len(data)==0 or data=="Query rate limit exceeded":
				print thread_name+":"+"limit append to queue:"+thread_ip_list[i]
				#count=count+1
				#for query limite set sleep time
				# if last_limit_flag==0:
				# 	last_limit_flag=1
				# 	#limit_recode=0
				# elif last_limit_flag==1:
				# 	limit_recode=limit_recode+1
				# 	if limit_recode==100:
				# 		print thread_name+' sleep for 100s'
				# 		sleep(limit_recode)
				# 	elif  limit_recode>100:
				# 		limit_recode=limit_recode*2
				# 		print thread_name+' sleep:'+str(limit_recode)+'s'
				# 		sleep(limit_recode)
				ip_push_into_queue(thread_ip_list[i])
				continue
			#deal both have ' and " in data
			#for query limite set sleep time
			# last_limit_flag=0
			# if limit_recode>0:
			# 	limit_recode=limit_recode/2
			if '"' in data:
				data=data.replace('"','\\"')
			data='{"content":"'+data+'","ip":"'+thread_ip_list[i]+'"}'
			if write_result_lock.acquire(True):
				wr_fp.write(data)
				wr_fp.write('\n')
				#wr_fp.flush()
				write_result_lock.release()
			query_limits_count=query_limits_count-1
			#for query limit for everyday
			if query_limits_count<=0:
				query_limits_count=1000
				sleep(86400)
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
def main():
	if __name__=='__main__':
		#break_thread_signal=0
		i=0
		#break_thread_signal=0
		global ip_list,wr_fp,wl_fp,break_thread_signal,fetch_count
		recover()

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
main()

