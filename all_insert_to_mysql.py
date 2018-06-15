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
import netaddr
from pymongo import MongoClient
import  MySQLdb
def deal_arin_mysql():
    print "Begin insert arin to db..."
    db = MySQLdb.connect("localhost", "root", "", "whois_inetnum", charset='utf8' )
    cursor = db.cursor()
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
    cidr_sums=0
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
                        content=content.encode('string-escape')
                        sql = "INSERT INTO arin(id,ip_begin,ip_end, content, time) \
                            VALUES('%d','%d','%d','%s','%s')" % \
                            (sums,ip_begin, ip_end, content, insert_time)
                        cursor.execute(sql)

                        cidrs = netaddr.iprange_to_cidrs(ip_range[0][0], ip_range[0][1])
                        for k, v in enumerate(cidrs):
                            iplist = str(v)
                            cidr=iplist.split('/')
                            if len(cidr)==2:
                                cidr_ip_num=int(socket.ntohl(struct.unpack("I",socket.inet_aton(str(cidr[0])))[0]))
                                cidr_tail_num=int(socket.ntohl(struct.unpack("I",socket.inet_aton(str(cidr[1])))[0]))
                                if cidr_tail_num>0 and cidr_tail_num<=32:
                                    cidr_sums=cidr_sums+1;
                                    cidr_ip_predix=cidr_ip_num & (~((1<<(32-cidr_tail_num))-1))
                                    sql_cidr = "INSERT INTO arin_cidr(id,fid, ip_range_predix) \
                                        VALUES('%d','%d','%d')" % \
                                        (cidr_sums, sums, cidr_ip_predix)
                                    cursor.execute(sql_cidr)
                        if sums %10000==0:
                            db.commit()
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
    db.commit()
    print "end insert arin to db:"+str(sums)
    fr.close()
def insert_ripe_into_msyql():
    print "Begin insert ripe db..."
    db = MySQLdb.connect("localhost", "root", "", "whois_inetnum", charset='utf8' )
    cursor = db.cursor()

    dic={}
    reg=r'(?:inetnum {0,1}: {0,10})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9]))) {0,13}- {0,4}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))'
    #reg=r'inetnum.+(*).+-'
    fr=open('./ripe.db.inetnum','r')
    
    fr.seek(0,0)
    sums=0
    all_ip=0
    content=""
    insert_time=str(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime()))
    while True:
        line=fr.readline()
        if line=="\n":
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
                    fencoding=chardet.detect(content)   #一个破文件，里面什么编码都有，fuck
                    #将内容按照unicode-escape格式解码成unicode,unicode-escape是unicode得内存编码值
                    try:                                        #使用decode('unicode-escape')解码，遇到/N /U /u其后字符不符标准，转义会失败      
                        content=content.encode('string-escape')
                        sql = "INSERT INTO arin(ip_begin,ip_end, content, time) \
                            VALUES('%d','%d','%s','%s')" % \
                            (ip_begin, ip_end, content, insert_time)
                        cursor.execute(sql)
                    except Exception as e:
                        print e
                        print 'find \N or \u or \U unicodeescape can not deal!'
                        content=re.sub("\\\N", "\\\\\N", content)   #如果用decode('unicode-escape')，那么content不能存在\N或\U或\u这种转义符,                   
                        content=re.sub("\\\u", "\\\\\u", content)   #如果存在这些符号，后面跟的内容必须是正确的转义规则所指的内容
                        content=re.sub("\\\U", "\\\\\U", content)   #如果使用sub("\N", "\\N", content)，并不仅仅匹配\N，还会匹配所有的N                               
                        content=content.encode('string-escape')
                        sql = "INSERT INTO ripe(ip_begin,ip_end, content, time) \
                            VALUES('%d','%d','%s','%s')" % \
                            (ip_begin, ip_end, content, insert_time)
                        cursor.execute(sql)
                    if sums %10000==0:
                        db.commit()
                    #break
                    #print str(ip_begin)+"~"+str(ip_end)
                else:
                    print "unfair:"+arr[0]
            else:
                print "header:"+arr[0]
            #print arr[0]
            content=""
        elif line=="":
            break
        else:
            content=content+line
    db.commit()
    print sums
    print "End insert ripe to db..."
    fr.close()
def insert_afrinic_into_mysql():
    print "Begin insert afrinic db..."
    db = MySQLdb.connect("localhost", "root", "", "whois_inetnum", charset='utf8' )
    cursor = db.cursor()

    dic={}
    reg=r'(?:inetnum {0,1}: {0,10})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9]))) {0,13}- {0,4}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))'
    #reg=r'inetnum.+(*).+-'
    fr=open('./afrinic.db','r')
    
    fr.seek(0,0)
    sums=0
    all_ip=0
    content=""
    insert_time=str(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime()))
    while True:
        line=fr.readline()
        if line=="\n":
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
                    fencoding=chardet.detect(content)   #一个破文件，里面什么编码都有，fuck
                    #将内容按照unicode-escape格式解码成unicode,unicode-escape是unicode得内存编码值
                    try:                                        #使用decode('unicode-escape')解码，遇到/N /U /u其后字符不符标准，转义会失败      
                        content=content.encode('string-escape')
                        #content=content.decode('unicode-escape')
                        #content=content.decode(fencoding['encoding']).encode("utf-8") 
                        sql = "INSERT INTO afrinic(ip_begin,ip_end, content, time) \
                            VALUES('%d','%d','%s','%s')" % \
                            (ip_begin, ip_end, content, insert_time)
                        cursor.execute(sql)
                    except Exception as e:
                        print e
                        print 'find \N or \u or \U unicodeescape can not deal!'
                        content=re.sub("\\\N", "\\\\\N", content)   #如果用decode('unicode-escape')，那么content不能存在\N或\U或\u这种转义符,                   
                        content=re.sub("\\\u", "\\\\\u", content)   #如果存在这些符号，后面跟的内容必须是正确的转义规则所指的内容
                        content=re.sub("\\\U", "\\\\\U", content)   #如果使用sub("\N", "\\N", content)，并不仅仅匹配\N，还会匹配所有的N                               
                        #content=content.decode('string-escape')
                        content=content.encode('unicode-escape')
                        sql = "INSERT INTO afrinic(ip_begin,ip_end, content, time) \
                            VALUES('%d','%d','%s','%s')" % \
                            (ip_begin, ip_end, content, insert_time)
                        cursor.execute(sql)
                    if sums %10000==0:
                        db.commit()
                    #break
                    #print str(ip_begin)+"~"+str(ip_end)
                else:
                    print "unfair:"+arr[0]
            else:
                print arr[0]
            #print arr[0]
            content=""
        elif line=="":
            break
        else:
            content=content+line
    db.commit()
    print sums
    print "End insert afrinic to db..."
    fr.close()
def insert_apnic_into_mysql():
    print "Begin insert apnic mysql..."
    db = MySQLdb.connect("localhost", "root", "", "whois_inetnum", charset='utf8' )
    cursor = db.cursor()
    dic={}
    reg=r'(?:inetnum {0,1}: {0,10})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9]))) {0,13}- {0,4}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))'
    #reg=r'inetnum.+(*).+-'
    fr=open('./apnic.db.inetnum','r')
    
    fr.seek(0,0)
    sums=0
    cidr_sums=0;
    all_ip=0
    content=""
    insert_time=str(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime()))
    while True:
        line=fr.readline()
        if line=="\n":
            #sums=sums+1
            #print content
            #fencoding=chardet.detect(content)
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
                    #fencoding=chardet.detect(content)   #一个破文件，里面什么编码都有，fuck
                    #将内容按照unicode-escape格式解码成unicode,unicode-escape是unicode得内存编码值
                    try:                                        #使用decode('unicode-escape')解码，遇到/N /U /u其后字符不符标准，转义会失败      
                        #content=content.decode('unicode-escape')
                        content=content.encode('string-escape')
                        #print  "after:"+str(fencoding['encoding'])
                        #先用string 编码，要获得正确输出，先用string解码，再用gbk编码
                        #if ip_range[0][0]=="210.77.169.72":
                            #apnic is gbk
                        #content=content.decode('gbk')
                        sql = "INSERT INTO apnic(id,ip_begin,ip_end, content, time) \
                            VALUES('%d','%d','%d','%s','%s')" % \
                            (sums,ip_begin, ip_end, content, insert_time)
                        cursor.execute(sql)

                        cidrs = netaddr.iprange_to_cidrs(ip_range[0][0], ip_range[0][1])
                        for k, v in enumerate(cidrs):
                            iplist = str(v)
                            cidr=iplist.split('/')
                            if len(cidr)==2:
                                cidr_ip_num=int(socket.ntohl(struct.unpack("I",socket.inet_aton(str(cidr[0])))[0]))
                                cidr_tail_num=int(socket.ntohl(struct.unpack("I",socket.inet_aton(str(cidr[1])))[0]))
                                if cidr_tail_num>0 and cidr_tail_num<=32:
                                    cidr_sums=cidr_sums+1;
                                    cidr_ip_predix=cidr_ip_num & (~((1<<(32-cidr_tail_num))-1))
                                    sql_cidr = "INSERT INTO apnic_cidr(id,fid, ip_range_predix) \
                                        VALUES('%d','%d','%d')" % \
                                        (cidr_sums, sums, cidr_ip_predix)
                                    cursor.execute(sql_cidr)
                    except Exception as e:
                        print e
                        # print 'find \N or \u or \U unicodeescape can not deal!'
                        # content=re.sub("\\\N", "\\\\\N", content)   #如果用decode('unicode-escape')，那么content不能存在\N或\U或\u这种转义符,                   
                        # content=re.sub("\\\u", "\\\\\u", content)   #如果存在这些符号，后面跟的内容必须是正确的转义规则所指的内容
                        # content=re.sub("\\\U", "\\\\\U", content)   #如果使用sub("\N", "\\N", content)，并不仅仅匹配\N，还会匹配所有的N                               
                        # #content=content.decode('unicode-escape')
                        # content=content.encode('string-escape')
                        # sql = "INSERT INTO apnic(id,ip_begin,ip_end, content, time) \
                        #     VALUES('%d','%d','%d','%s','%s')" % \
                        #     (sums,ip_begin, ip_end, content, insert_time)
                        # cursor.execute(sql)
                    if sums % 10000==0:
                        db.commit()
                        
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
    db.commit()
    print sums
    print "End insert apnic to db..."
    fr.close()
#insert_apnic_into_mysql()
#insert_afrinic_into_mysql()
#insert_ripe_into_msyql()
deal_arin_mysql()