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
	tp=open("/home/ly/pcap_reader/tcpdump_icmp_1.live.left_ttl","r")
	sp=open("/home/ly/scan_data/1.live.warts.txt.extract.hop.useful","r")
	tcpdump_ip_ttl_list={}
	trace_ip_hop_list={}
	while 1:
		line = tp.readline()
		if not line:
			break
		ip_ttl=line.strip().split()
		if len(ip_ttl)==2:
			if tcpdump_ip_ttl_list.has_key(ip_ttl[0]) and (ip_ttl[1] not in tcpdump_ip_ttl_list[ip_ttl[0]]):
				tcpdump_ip_ttl_list[ip_ttl[0]].append(ip_ttl[1])
			else:
				tcpdump_ip_ttl_list[ip_ttl[0]]=[]
				tcpdump_ip_ttl_list[ip_ttl[0]].append(ip_ttl[1])
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
				trace_ip_hop_list[ip_hop[0]]=ip_hop[2]
			else:
				trace_last_not_same=trace_last_not_same+1
	ip_multi_ttl=0
	for key in tcpdump_ip_ttl_list:
		print key+":",
		if len(tcpdump_ip_ttl_list[key])>1:
			ip_multi_ttl=ip_multi_ttl+1
		for ttl in tcpdump_ip_ttl_list[key]:
			print ttl,
		print '\n'
	ip_multi_hop=0
	for key in trace_ip_hop_list:
		print key+":"+trace_ip_hop_list[key]

	print "trace_last_not_same:",
	print trace_last_not_same
	print "trace_last_same:",
	print trace_last_same
	print "ip_multi_ttl:",
	print ip_multi_ttl
	print "ip_multi_hop:",
	print ip_multi_hop
	equal_ttl_hop(trace_ip_hop_list,tcpdump_ip_ttl_list)
def equal_ttl_hop(trace_ip_hop_list,tcpdump_ip_ttl_list):
	sum=0
	equal_num=0
	for key in tcpdump_ip_ttl_list:
		if trace_ip_hop_list.has_key(key):
			sum=sum+1
			if (int(trace_ip_hop_list[key])-1) == (64-int(tcpdump_ip_ttl_list[key][0])):
				equal_num=equal_num+1
			else:
				print (int(trace_ip_hop_list[key])-1),
				print (64-int(tcpdump_ip_ttl_list[key][0]))

	print equal_num
	print sum
if __name__=="__main__":
	comfirm_ttl()