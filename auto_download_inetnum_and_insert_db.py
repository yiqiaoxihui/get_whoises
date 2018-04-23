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

global apnic_download_file,arin_download_file
arin_download_file="arin_nets.zip"
apnic_download_file= "apnic.db.inetnum.gz"
global log_filename
log_filename="wget_download_whois_inetnum_log.txt"


def insert_apnic_into_db():
    print "Begin insert apnic db..."
    log=open(log_filename,'a')
    conn=MongoClient('127.0.0.1',27017)
    db=conn.ly
    #ripe=db.ripe
    apnic=db.apnic
    apnic.drop()
    dic={}
    reg=r'(?:inetnum {0,1}: {0,10})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9]))) {0,13}- {0,4}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))'
    #reg=r'inetnum.+(*).+-'
    if os.path.isfile("./apnic.db.inetnum")==False:
        log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nNot find when insert into db:apnic.db.inetnum+\n")
        return
    fr=open('./apnic.db.inetnum','r')
    fencoding=chardet.detect(fr.readline())
    fr.seek(0,0)
    #fw=open('./apnic_inetnum','w')
    sums=0
    all_ip=0
    content=""
    #t=time.strptime('2011-05-05 16:37:06', '%Y-%m-%d %X')
    #time.mktime(t)
    log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nBegin insert into db:apnic.db.inetnum\n")
    insert_time=str(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime()))
    while True:
        line=fr.readline()
        if line=="\n":
            #sums=sums+1
            #print content
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
                        content=content.decode('unicode-escape')
                        #content=content.encode('string-escape')
                        #print  "after:"+str(fencoding['encoding'])
                        #先用string 编码，要获得正确输出，先用string解码，再用gbk编码
                        #if ip_range[0][0]=="210.77.169.72":
                            #apnic is gbk
                        #content=content.decode('gbk')
                        apnic.insert({"ip_begin":ip_begin,"ip_end":ip_end,"content":content,"time":insert_time})
                    except Exception as e:
                        print e
                        print 'find \N or \u or \U unicodeescape can not deal!'
                        content=re.sub("\\\N", "\\\\\N", content)   #如果用decode('unicode-escape')，那么content不能存在\N或\U或\u这种转义符,                   
                        content=re.sub("\\\u", "\\\\\u", content)   #如果存在这些符号，后面跟的内容必须是正确的转义规则所指的内容
                        content=re.sub("\\\U", "\\\\\U", content)   #如果使用sub("\N", "\\N", content)，并不仅仅匹配\N，还会匹配所有的N                               
                        content=content.decode('unicode-escape')
                        apnic.insert({"ip_begin":ip_begin,"ip_end":ip_end,"content":content,"time":insert_time})
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
    log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nComplete insert into db:apnic.db.inetnum\n")
    fr.close()
    log.close()
def un_gz():
    print "Begin extract apnic..."
    log=open(log_filename,'a')
    if os.path.exists(apnic_download_file):
        log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nExtract apnic file:\n")
        log.flush()
        if os.path.exists(apnic_download_file[:-3]):
            os.remove(apnic_download_file[:-3])
        if os.system("gunzip "+apnic_download_file)==0:
            log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nExtract apnic file success:\n")
        if os.path.exists(apnic_download_file):
            os.remove(apnic_download_file)#unzip remove auto
    else:
        log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nNot find apnic file:\n")
        log.flush()
    log.close()
    print "End extract apnic..."
    # """ungz zip file"""  
    # f_name = file_name.replace(".gz", "")  
    # #获取文件的名称，去掉  
    # g_file = gzip.GzipFile(file_name)  
    # #创建gzip对象  
    # open(f_name, "w+").write(g_file.read())  
    # #gzip对象用read()打开后，写入open()建立的文件中。  
    # g_file.close()

    #关闭gzip对象
def retrieving_apnic():
    '''Download data'''
    log= open(log_filename,'a')
    #os.chdir(outpath) change current work dir
    #print(os.curdir)
    #just one neet to download
    try:
        cmd = 'wget -c ftp://ftp.apnic.net/public/apnic/whois/'+apnic_download_file    
        print cmd
        #print "begin"
        log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+'\nBegin apnic download:'+apnic_download_file+"\n")
        log.flush()
        status = subprocess.call(cmd,shell=True)
        if status !=0:
            print "Download apnic failed:"+apnic_download_file
            log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+'\nDownload apnic failed:'+apnic_download_file+"\n")
            log.flush()
        else:
            print "Download apnic success:"+apnic_download_file
            log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+'\nDownload apnic success:'+apnic_download_file+"\n")
            log.flush()
    except:
        print "Download apnic except!"
        log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+'\nDowndlaod apnic except:'+apnic_download_file+"\n")
    log.close()

def do_apnic():
    retrieving_apnic()
    un_gz()
    #insert_apnic_into_db()

    # for i in raw_resource_list:
    #     if os.path.exists(i):
    #         #删除文件，可使用以下两种方法。
    #         os.remove(i)
    #     if os.path.exists(i[:-3]):
    #         os.remove(i[:-3])
def deal_arin():
    print "Begin insert arin to db..."
    log=open(log_filename,'a')
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
    #first,judge it code type,then change to utf-8
    fencoding=chardet.detect(fr.readline())
    fr.seek(0,0)
    #fw=open('./apnic_inetnum','w')
    sums=0
    all_ip=0
    content=""
    #t=time.strptime('2011-05-05 16:37:06', '%Y-%m-%d %X')
    #time.mktime(t)
    log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nBegin insert arin into db\n")
    insert_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) 
    while True:
        line=fr.readline()
        if line=="\n":
            #sums=sums+1
            #print content
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
                        content=content.strip() #delete whitespace in head or tail
                        #content=content.decode(fencoding['encoding']).encode("utf-8")
                        #content=content.encode('string-escape')#can be use
                        #不转码也未出错
                        arin.insert({"ip_begin":ip_begin,"ip_end":ip_end,"content":content,"time":insert_time})
                        #print str(ip_begin)+"~"+str(ip_end)
                        break
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
    log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nend insert arin into db:"+str(sum)+"\n")
    fr.close()
    log.close()

def retrieve_arin():
    log= open(log_filename,'a')
    try:
        cmd = "wget -c 'https://www.arin.net/public/secure/downloads/bulkwhois/nets.zip?apikey=API-C592-1B4C-4E7E-B45E' -O "+arin_download_file
        print cmd
        #print "begin"
        log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nBegin download arin:\n")
        log.flush()
        status = subprocess.call(cmd,shell=True)
        if status !=0:
            print "Download arin failed:"
            log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nDownload arin failed:\n")
            log.flush()
        else:
            print "Download arin success:"+each_item
            log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nDownload arin success\n")
            log.flush()
    except:
        print "Download arin except!"
        log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nDowndlaod arin except\n")
    log.close()
def unzip_arin():
    log=open(log_filename,'a')
    if os.path.exists(arin_download_file):
        log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nExtract arin file:\n")
        log.flush()
        if os.path.exists("arin_db.txt"):
            os.remove("arin_db.txt")
        if os.system("unzip arin_nets.zip arin_db.txt")==0:
            log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nExtract arin file success:\n")
        if os.path.exists(arin_download_file):
            os.remove(arin_download_file)#delete old file
    else:
        log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nNot find arin file:\n")
        log.flush()
    log.close()

def do_arin():
    retrieve_arin()
    unzip_arin()
    #deal_arin()
def wait():
    day=datetime.datetime.now().day
    apnic_left=(14-day+30)%30
    arin_left=(19-day+30)%30
    s1="wait for next update(apnic,arin left "+str(apnic_left)+","+str(arin_left)+"day)\r"
    s2="wait for next update(apnic,arin left "+str(apnic_left)+","+str(arin_left)+"day).\r"
    s3="wait for next update(apnic,arin left "+str(apnic_left)+","+str(arin_left)+"day)..\r"
    s4="wait for next update(apnic,arin left "+str(apnic_left)+","+str(arin_left)+"day)...\r"

    os.system("clear")
    print s1
    time.sleep(0.5)
    os.system("clear")
    print s2
    time.sleep(0.5)
    os.system("clear")
    print s3 
    time.sleep(0.5)
    os.system("clear")
    print s4
    time.sleep(0.5) 
    
    # #os.system("clear")
    # time.sleep(0.5)
def main():
    while True:
        day=datetime.datetime.now().day
        if day==14:
            log= open(log_filename,'a')
            print "Begin update apnic ..."
            log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\n\n\n\nBegin update apnic...\n")
            log.flush()
            do_apnic()
            print "End apnic update..."
            log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nEnd apnic update...\n\n\n\n\n")
            log.flush()
            log.close()
            time.sleep(84600)
        elif day==19:
            log= open(log_filename,'a')
            print "Begin update arin ..."
            log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\n\n\n\Begin arin update...\n")
            log.flush()
            do_arin()
            print "End arin update..."
            log.write(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())+"\nEnd arin update...\n\n\n\n\n")
            log.flush()
            log.close()
            time.sleep(84600)
        else:
            wait()
if __name__  =='__main__':
    #outpath="/home/hitnis/Document/whois-whois-1.87/dump/"
    main()



