#-*-coding:utf-8 -*-
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

def deal_arin():
    print "Begin insert arin to db..."
    conn=MongoClient('127.0.0.1',27017)
    db=conn.ly
    #ripe=db.ripe
    arin=db.arin
    #afrinic=db.afrinic
    #arin=db.arin
    dic={}
    reg=r'(?:NetRange {0,1}: {0,10})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9]))) {0,13}- {0,4}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))'
    #reg=r'inetnum.+(*).+-'
    fr=open('./arin_db.txt','r')
    fencoding=chardet.detect(fr.readline())
    print fencoding['encoding']
    fr.seek(0,0)
    #fw=open('./apnic_inetnum','w')
    sums=0
    all_ip=0
    content=""
    #t=time.strptime('2011-05-05 16:37:06', '%Y-%m-%d %X')
    #time.mktime(t)
    insert_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) 
    while True:
        line=fr.readline()

        if line=="\n":
            #sums=sums+1
            #print content
            fencoding=chardet.detect(content)
            if fencoding['encoding']!='ascii':
                print fencoding['encoding']
            arr=content.strip().split("\n")
            for item in arr:
                if item[0:8]=="NetRange":
                    ip_range=re.findall(reg,item)
                    if ip_range!=[]:
                        sums=sums+1
                        #print ip_range[0][0]+"~"+ip_range[0][1]
                        ip_begin=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_range[0][0])))[0])
                        ip_end=socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_range[0][1])))[0])
                        content=re.sub("\n{3,}","\n\n",content)
                        content=re.sub(" {2,}", " ", content)
                        #print content
                        #content=content.decode(fencoding['encoding']).encode("utf-8")

                        #apnic is gbk
                        #content=content.decode('gbk')
                        arin.insert({"ip_begin":ip_begin,"ip_end":ip_end,"content":content,"time":insert_time})
                        #print str(ip_begin)+"~"+str(ip_end)
                    else:
                        #
                        #print item
                        break
            #print arr[0]
            content=""
        elif line=="":
            break
        else:
            content=content+line
    print "end insert arin to db:"+str(sum)
    fr.close()
deal_arin()