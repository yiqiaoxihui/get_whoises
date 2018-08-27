#!/usr/bin/env python
# -*- coding:utf-8 -*-
import os
import os.path
import sys
import subprocess
import time
import gzip
import datetime
import re
import struct
import socket
import chardet

def comfirm_ttl():
	file_path_icmp=sys.argv[1]
	file_path_scamper=sys.argv[2]
	tp=open(file_path_icmp,"r")
	sp=open(file_path_scamper,"r")
	tcpdump_ip_ttl_list={}
	trace_ip_hop_list={}
	while 1:
		line = tp.readline()
		if not line:
			break
		ip_ttl=line.strip().split()
		if len(ip_ttl)==2:
			int_ttl=int(ip_ttl[1])
			if tcpdump_ip_ttl_list.has_key(ip_ttl[0]):
				if (int_ttl not in tcpdump_ip_ttl_list[ip_ttl[0]]):
					tcpdump_ip_ttl_list[ip_ttl[0]].append(int_ttl)
				else:
					#print ip_ttl[0]
					pass
			else:
				tcpdump_ip_ttl_list[ip_ttl[0]]=[]
				tcpdump_ip_ttl_list[ip_ttl[0]].append(int_ttl)

	trace_last_not_same=0
	trace_last_same=0
	while 1:
		line = sp.readline()
		if not line:
			break
		ip_hop=line.strip().split()
		if len(ip_hop)==3:
			if ip_hop[0]==ip_hop[1]:
				trace_last_same=trace_last_same+1
				trace_ip_hop_list[ip_hop[0]]=int(ip_hop[2])
			else:
				print ip_hop[0],
				print ip_hop[1]
				trace_last_not_same=trace_last_not_same+1
	ip_multi_ttl=0
	ttl_gt_64=0
	fp_muti_ttl=open("2.live.65535.muti.ttl.txt","w")
	for key in tcpdump_ip_ttl_list:
		if len(tcpdump_ip_ttl_list[key])>1:
			ip_multi_ttl=ip_multi_ttl+1
			print key+":",
			str_muti_ttl=key
			for ttl in tcpdump_ip_ttl_list[key]:
				print ttl,
				str_muti_ttl=str_muti_ttl+" "+str(ttl)
			print '\n',
			fp_muti_ttl.write(str_muti_ttl+"\n")
		#打印ttl>64的
		if sum(tcpdump_ip_ttl_list[key])/len(tcpdump_ip_ttl_list[key])>=64:
			ttl_gt_64=ttl_gt_64+1
			# print key+":",
			# for ttl in tcpdump_ip_ttl_list[key]:
			# 	print ttl,
			# print '\n',
	# for key in trace_ip_hop_list:
	# 	print key+":"+trace_ip_hop_list[key]
	print "ttl_gt_64:",
	print ttl_gt_64
	print "trace_last_not_same:",
	print trace_last_not_same
	print "trace_last_same:",
	print trace_last_same
	print "ip_multi_ttl:",
	print ip_multi_ttl
	print "tcpdump_ip_ttl_list:",
	print len(tcpdump_ip_ttl_list)
	tp.close()
	sp.close()
	fp_muti_ttl.close()
	equal_ttl_hop(trace_ip_hop_list,tcpdump_ip_ttl_list)
def equal_ttl_hop(trace_ip_hop_list,tcpdump_ip_ttl_list):
	sum=0
	equal_num=0
	unequal_num=0
	ttl_dis_dic={}
	fp_unequal=open("2.live.65535.ttl.unequal.txt",'w')
	for key in tcpdump_ip_ttl_list:
		if trace_ip_hop_list.has_key(key):
			sum=sum+1
			if 64-(trace_ip_hop_list[key]-1) in (tcpdump_ip_ttl_list[key]):
				equal_num=equal_num+1
			else:
				unequal_num=unequal_num+1
				fp_unequal.write(key+"\n")
				dis=64-(trace_ip_hop_list[key]-1)-tcpdump_ip_ttl_list[key][0]
				if ttl_dis_dic.has_key(dis):
					ttl_dis_dic[dis]=ttl_dis_dic[dis]+1
				else:
					ttl_dis_dic[dis]=1
				# print "ip:"+key+":",
				# print "hop:"+str(trace_ip_hop_list[key]-1)+"ttl:",
				# for ttl in tcpdump_ip_ttl_list[key]:
				# 	print 64-ttl,
				# print '\n',

	for key in ttl_dis_dic:
		print "ttl:",
		print key,
		print "num:",
		print ttl_dis_dic[key]
	print "trace_ip_hop_list:",
	print len(trace_ip_hop_list)
	print "tcpdump_ip_ttl_list:",
	print len(tcpdump_ip_ttl_list)
	print "equal_num:",
	print equal_num
	print "unequal_num",
	print unequal_num
	print "sum:",
	print sum
	fp_unequal.close()
if __name__=="__main__":
	comfirm_ttl()