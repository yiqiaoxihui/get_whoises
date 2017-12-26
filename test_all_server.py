import re
import os
import socket
import struct
import hashlib
import threading

ripe_servers[
    "whois.ripe.net",
    "whois.apnic.net",
    "whois.afrinic.net",
    "whois.arin.net",	
    "whois.lacnic.net",
    "whois.nic.or.kr",
    "whois.twnic.net",
    "whois.nic.ad.jp",
]
server_ip=[]
server_dic={}
def do_query(ip,server,port=""):
	if server!="":
		arg="whois -h "+server+" "+ip
	else:
		arg="whois "+ip
	query_result=os.popen(arg)
	data=""
	for line in query_result:
		data=data+line
	data=re.sub("\n{3,}","\n\n",data)
	data=re.sub(" {2,}", " ", data)
	data=data.strip()							#delete whitespace in head or tail
	data=data.replace("\n","\\n")
	return data
def whois_query(server,ip):
	global server_dic
	while True:
		data=do_query(ip,server)
		if len(data)==0 or data=="Query rate limit exceeded" or data.find("access from your host has been permanently")>0:
			return
		else:
			if server_dic.has_key(server):
				server_dic[server]=server_dic[server]+1
			else:
				server_dic[server]=1
	print server +":"+str(server_dic[server])
def main():
	thread_count=len(ripe_servers)
	for i in range(0,thread_count):
		t = threading.Thread(target=whois_query,args=(ripe_servers[i],))
		query_threads.append(t)
	#run multithread 
	for t in query_threads:
		t.setDaemon(False)		#
		t.start()
	threading.Thread(target=break_keep).start()
	for t in query_threads:
		t.join()
	print server_dic