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
from pymongo import MongoClient


def insert_apnic_into_db():
    print "Begin insert apnic db..."
    conn=MongoClient('127.0.0.1',27017)
    db=conn.ly
    #ripe=db.ripe
    apnic=db.apnic
    #delete before insert update
    apnic.drop()

    dic={}
    reg=r'(?:inetnum {0,1}: {0,10})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9]))) {0,13}- {0,4}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))'
    #reg=r'inetnum.+(*).+-'
    fr=open('./apnic.db.inetnum','r')

    fr.seek(0,0)
    sums=0
    all_ip=0
    content=""
    insert_time=str(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime()))
    while True:
        line=fr.readline()
        if line=="\n":
            #sums=sums+1
            #print content
            fencoding=chardet.detect(content)
            #if fencoding['encoding']!='ascii':
            #    print fencoding['encoding']
            arr=content.strip().split("\n")
            if arr[0][0:7]=="inetnum":
                ip_range=re.findall(reg,arr[0])
                if ip_range!=[]:
                    sums=sums+1
                    #print ip_range[0][0]+"~"+ip_range[0][1]
                    ip_begin=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_range[0][0])))[0])
                    ip_end=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_range[0][1])))[0])
                    content=re.sub("\n{3,}","\n\n",content)
                    content=re.sub(" {2,}", " ", content)    
                    #content=content.decode(fencoding['encoding']).encode("utf-8")
                    content=content.encode('string-escape')
                    fencoding=chardet.detect(content)
                    print  "after:"+str(fencoding['encoding'])
                    #先用string 编码，要获得正确输出，先用string解码，再用gbk编码
                    #if ip_range[0][0]=="210.77.169.72":
                        #apnic is gbk
                    #content=content.decode('gbk')
                    #apnic.insert({"ip_begin":ip_begin,"ip_end":ip_end,"content":content,"time":insert_time})
                    #break
                    #print str(ip_begin)+"~"+str(ip_end)
            else:
                print arr[0]
            #print arr[0]
            content=""
        elif line=="":
            break
        else:
            content=content+line
    print sums
    print "End insert apnic to db..."
    fr.close()
insert_apnic_into_db()
