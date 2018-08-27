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
	file_path=sys.argv[1]
	fr=open(file_path,'r')
	hop_file_path=file_path+".star.hop"
	useful_hop_file_path=file_path+".useful.hop"
	diff_hop_file_path=file_path+".unreach.hop"
	fw=open(hop_file_path,'w')
	fuw=open(useful_hop_file_path,'w')
	fud=open(diff_hop_file_path,'w')
	fr.seek(0,0)
	sums=0
	star_hop=0;
	diff_last_hop=0
	same_last_hop=0
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
				if last_hop_ip!="*":
					if pre_traceroute_ip==last_hop_ip:
						fuw.write(pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num+'\n')
						print pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num
						same_last_hop=same_last_hop+1
					else:
						diff_last_hop=diff_last_hop+1
						#fud.write(pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num+'\n')
						fud.write(pre_traceroute_ip+'\n')
				else:
					#fw.write(pre_traceroute_ip+" "+last_hop_ip+" "+last_hop_num+'\n')
					fud.write(pre_traceroute_ip+'\n')
					star_hop=star_hop+1
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
	print "sums:",
	print sums
	print "star_hop:",
	print star_hop
	print "diff_last_hop:",
	print diff_last_hop
	print "same_last_hop:",
	print same_last_hop
	print "End ..."
	fr.close()
	fw.close()
	fuw.close()
if __name__=="__main__":
	extract_traceroute_get_last_hop()
