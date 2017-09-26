## -*- coding: utf-8 -*-
"""
Created on Thu sep 24 17:42:49 2017

@author: ly
"""
import os
import re
#import requests
import json
import threading
import collections


def main():
	if __name__=='__main__':
		#end_thread_signal=0

		#global ip_list
		end_thread_signal=0
		ip_path=raw_input("please input ip file path:")
		result_path=raw_input("please input result path:")

		result_path="/data/all_ip_90w"
		ip_path='/data/20170706.origins'

		ip_in_row=0
		ip_fp=open(ip_path,'r')
		w_fp=open(result_path,'w')

		ip_list=ip_fp.readlines()
		ip_fp.close()
		ip_count=len(ip_list)
		print ip_count
		for i in range(0,ip_count):
			ip_list[i]=ip_list[i].split()[0]
			ip_list[i]=ip_list[i].strip()
		last_ip_list=[]
		ip_dic=collections.OrderedDict()
		for ip in ip_list:
			ip_dic[ip]=1
		
		# for ip in ip_list:
		# 	print ip
		# 	while(ip_list.count(ip)>1):
		# 		del ip_list[ip_list.index(ip)]
		last_ip_list=ip_dic.keys()
		# for ip in ip_list:
		# 	print ip
		# 	if ip not in last_ip_list:
		# 		last_ip_list.append(ip)
		ip_range=[]
		ip_count=len(last_ip_list)
		print ip_count
		for ip in last_ip_list:
			ip_range=re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})",ip)
			#print ip_range
			if len(ip_range)>=1 and int(ip_range[0][1])>=24:
				continue
			w_fp.write(ip)
			w_fp.write("\n")
		


main()

