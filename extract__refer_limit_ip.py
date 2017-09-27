import re
import os
import socket
import struct
import hashlib
from pymongo import MongoClient





soure_file_path=raw_input("please input soure file path:")
des_file_path=raw_input("please input des file path:")
ip_out_put_path=raw_input("please input output ip path:")
s_fp=open(soure_file_path,'r')#/home/ly/Documents/all
d_fp=open(des_file_path,'w')
i_fp=open(ip_out_put_path,'w')
limit_fp=open('/data/refer_query_limit','w')
key_str="Found a referral to"
ip_count=0
left=0
while True:
    line = s_fp.readline()
    if line=="":
        break
    else:
		dic=eval(line)
		content=dic['content']#(\d+.\d+.\d+.\d+) - (\d+.\d+.\d+.\d+)
		position=content.find(key_str)
		if position>0 and len(content)-position-19<50:
			i_fp.write(dic['ip'])
			i_fp.write('\n')
			limit_fp.write(line)
			ip_count=ip_count+1
		else:
			left=left+1
			d_fp.write(line)


