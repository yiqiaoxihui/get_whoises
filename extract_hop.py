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


def extract_traceroute_get_last_hop():
	print "Begin ..."
	dic={}
	reg_trace_ip=r'(?:traceroute from )((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9]))) {0,2}to {0,2}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))'
	#reg=r'inetnum.+(*).+-'
	reg_trace_last_hop=r'([1-9]+) {0,2}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9]))|(\*))'
	fr=open('./1.live.warts.txt','r')
	fw=open('./1.live.warts.txt.extract.hop','w')
	fuw=open('./1.live.warts.txt.extract.hop.useful','w')
	fr.seek(0,0)
	sums=0
	usums=0
	all_ip=0
	content=""
	pre_traceroute_ip=""
	line=fr.readline()
	if line[0:10]=="traceroute":
		ip_range=re.findall(reg_trace_ip,line)
		if ip_range!=[]:
			pre_traceroute_ip=ip_range[0][1]
			local_ip=ip_range[0][0]
	while True:
		prev_line=line
		line=fr.readline().strip()
		if line[0:10]=="traceroute":
			sums=sums+1
			last_hop_list=re.findall(reg_trace_last_hop,prev_line)
			if last_hop_list!=[]:
				last_hop_num=last_hop_list[0][0]
				last_hop_ip=last_hop_list[0][1]
				fw.write(pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num+'\n')
				if last_hop_ip!="*":
					fuw.write(pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num+'\n')
					print pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num
					usums=usums+1
			#
			ip_range=re.findall(reg_trace_ip,line)
			if ip_range!=[]:
				pre_traceroute_ip=ip_range[0][1]
				local_ip=ip_range[0][0]
			else:
				print "error trace:"+line
		elif line=="":
			last_hop_list=re.findall(reg_trace_last_hop,prev_line)
			if last_hop_list!=[]:
				last_hop_num=last_hop_list[0][0]
				last_hop_ip=last_hop_list[0][1]
				fw.write(pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num+'\n')
				print pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num
			break
		else:
			pass
	print sums
	print usums
	print "End ..."
	fr.close()
	fw.close()
	fuw.close()
if __name__=="__main__":
	extract_traceroute_get_last_hop()
