#!/usr/bin/env python
# -*- coding:utf-8 -*-
import sys, os
import socket, getopt, time
import re

opts, args = getopt.getopt(sys.argv[1:], "hi:f:F:o:q:", ["help", "ip=", "file=", "filter=", "output=", "query="])
output = "output.txt"
for o, a in opts:
  if o in ('-h', '--help'):
    helpdoc = "\
Usage: process.py [option] [arg]\n\
Options and arguments:\n\
-f,--file= FILENAME   : basic IP query\n\
-h,--help             : print this help message and exit\n\
-i,--ip= IPADDRESS    : print AS num and information of IP address\n\
-o,--output= FILENAME : filename of the output file, default is output.txt\n\
-q,--query= FILENAME  : IP query for zjy\n\
"
    print helpdoc
    sys.exit(0)
  elif o in ('-f', '--file'):
    command = "file"
    search = a
    isfile = os.path.isfile("./" + a)
    if isfile is False:
      print "No such file!"
      sys.exit(0)
  elif o in ('-F', '--filter'):
    command = "filter"
    search = a
    isfile = os.path.isfile("./" + a)
    if isfile is False:
      print "No such file!"
      sys.exit(0)
  elif o in ('-q', '--query'):
    command = "query"
    search = a
    isfile = os.path.isfile("./" + a)
    if isfile is False:
      print "No such file!"
      sys.exit(0)
  elif o in ('-i', '--ip'):
    command = "ipaddr"
    search = a
  elif o in ('-o', '--output'):
    output = a
ip_port = ('10.10.11.233',1234)
sk = socket.socket()
sk.connect(ip_port)
sk.sendall(command)
time.sleep(1) 
if command == "ipaddr":
  sk.sendall(search)
  data = sk.recv(1024)
  print data
elif command == "file":
  with open(search, 'rb') as inputfile:
    while True:
      data = inputfile.read(4096)
      if not data:
        break
      sk.send(data)
  time.sleep(1)
  sk.send('EOF')
  with open(output, 'wb') as outputfile:
    while True:
      data = sk.recv(4096)
      if data == 'EOF':
        break
      outputfile.write(data)
    print "Received search result!"
elif command == "filter":
  with open(search, 'rb') as inputfile:
    while True:
      data = inputfile.read(4096)
      if not data:
        break
      sk.send(data)
  time.sleep(1)
  sk.send('EOF')
  with open(output, 'wb') as outputfile:
    while True:
      data = sk.recv(4096)
      if data == 'EOF':
        break
      outputfile.write(data)
    print "Received search result!"
elif command == "query":
  with open(search, 'rb') as inputfile:
    while True:
      data = inputfile.read(4096)
      if not data:
        break
      sk.send(data)
  time.sleep(1)
  sk.send('EOF')
  with open(output, 'wb') as outputfile:
    while True:
      data = sk.recv(4096)
      if data == 'EOF':
        break
      outputfile.write(data)
    print "Received search result!"

sk.close()
