#!/usr/bin/env python
from argparse import ArgumentParser
import sys
import os
import termcolor as T
from subprocess import Popen, PIPE
import re
import multiprocessing
from time import sleep, time
node_pat = re.compile(r'.*bash --norc -is mininet:(.*)')


def list_nodes(do_print=False):
    cmd = 'ps aux'
    proc = Popen(cmd.split(), stdout=PIPE)
    out, err = proc.communicate()
    # Mapping from name to pid.
    ret = {}
    for line in out.split('\n'):
        match = node_pat.match(line)
        if not match:
            continue
        name = match.group(1)
        pid = line.split()[1]
        if do_print:
            print "name: %6s, pid: %6s" % (name, pid)
        ret[name] = pid
    return ret
def bot_host_init(pid,hostname):
    os.system("mnexec -a %s python bot_sub.py" % pid)
    print "init bot:"+hostname
def control_host_init(pid,hostname):
    os.system("mnexec -a %s python bot_control.py" % pid)
    print "init control:"+hostname
def main():
    bot_ip_list=[]
    f = open('attack_info.txt','r')
    for line in f:
        if line[0] == '#':
            continue
        else:
            arg = line.strip().split(':')
            if arg[0] == 'attack_ip':
                attack_ip = arg[1]
            if arg[0] == 'bot_ip':
                for ip in arg[1].split():
                    bot_ip_list.append(ip)
    f.close()
    pid_by_name = list_nodes()
    bot_host=[]
    all_host=[]
    query_threads=[]
    for key in pid_by_name:
        if 'h' in key:
            all_host.append(key)
            ip=os.popen("mnexec -a %s ifconfig %s-eth0 | grep 'inet addr' | awk '{ print $2}' | awk -F: '{print $2}'" % (pid_by_name[key],key)).readlines()[0].strip()
            if ip in bot_ip_list:
                bot_host.append(key)
                #print "init bot:"+key
                t = multiprocessing.Process(target=bot_host_init,args=(pid_by_name[key],key,))
                query_threads.append(t)
                
    for t in query_threads:
        t.start()
    sleep(5)
    for host in all_host:
        if host not in bot_host:
            #print "init control:"+host
            multiprocessing.Process(target=control_host_init,args=(pid_by_name[host],key)).start()
            #query_threads.append(t)
            break
    for t in query_threads:
        t.join()
if __name__ == '__main__':
    main()
