#!/usr/bin/env python
# -*- coding: utf-8 -*-
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import lg, info, setLogLevel
from mininet.util import dumpNodeConnections, quietRun, moveIntf
from mininet.cli import CLI
from mininet.node import Switch, OVSKernelSwitch
from mininet.node import CPULimitedHost,Host
from mininet.link import TCLink
from subprocess import Popen, PIPE, check_output
from time import sleep, time
from multiprocessing import Process
from argparse import ArgumentParser

import sys
import os
import termcolor as T
import time
import socket
import struct
import re
setLogLevel('info')

parser = ArgumentParser("Configure 1 OSPF+BGP AS and 2 BGP only AS in Mininet.")
parser.add_argument('--sleep', default=3, type=int)
args = parser.parse_args()

def log(s, col="green"):
    print T.colored(s, col)

class Router(Switch):
    """Defines a new router that is inside a network namespace so that the
    individual routing entries don't collide.
    """
    ID = 0
    def __init__(self, name, **kwargs):
        kwargs['inNamespace'] = True
        Switch.__init__(self, name, **kwargs)
        Router.ID += 1
        self.switch_id = Router.ID

    @staticmethod
    def setup():
        print "router setup...."
        return

    def start(self, controllers):
        print "router start...."
        pass

    def stop(self):
        print "router stop...."
        self.deleteIntfs()

    def log(self, s, col="magenta"):
        print "router log...."
        print T.colored(s, col)

class SimpleTopo(Topo):
    def __init__(self):
        # Add default members to class.
        super(SimpleTopo, self ).__init__()
        num_hosts_per_router = 1 # The topology has one host per router
        routers = []
        hosts = []
        f1=open('topo/node.conf','r')
        f2=open('topo/link.conf','r')
        nodes=f1.readlines()
        links=f2.readlines()
        f1.close()
        f2.close()
        link_list=[]
        node_list=[]
        router_index=1
        host_id=1
        reg_node=r'(.*) #(.*)#(.*)'
        for link in links:
            link_list.append(link.split())
        for node in nodes:
            node_struct=re.findall(reg_node,node)[0]
            if node_struct!=[]:
                node_dic={}
                if node_struct[0]=='BGP' or node_struct[0]=='OSPF':
                    node_dic['name']='r'+str(router_index)
                    node_dic['router-id']=socket.inet_ntoa(struct.pack('I',socket.htonl(router_index)))
                    node_dic['type']=node_struct[0]
                    node_dic['eth_n']=node_struct[1].split('|')
                    node_dic['asn']=node_struct[2]
                    router_index=router_index+1
                    if router_index>=8589934592:
                        break
                elif node_struct[0]=='HOST':
                    node_dic['name']='h'+str(host_id)
                    host_id=host_id+1
                    node_dic['type']='HOST'
                    node_dic['eth_n']=node_struct[1].split('|')
                    node_dic['asn']=node_struct[2]
                else:
                    pass
                node_list.append(node_dic)

        router_bgp_dic={}
        router_ospf_dic={}
        router_zebra_dic={}
        current_host={}
        switch_index=1
        #just init router interface info
        for node in node_list:
            if node['type']=="BGP" or node['type']=="OSPF":
                router_name=node['name']
                self.addSwitch(router_name)
                router_zebra_dic[router_name]={}
                router_zebra_dic[router_name]['ethn']=[]
                router_zebra_dic[router_name]['log file']='/tmp/'+router_name+'.log'
                router_zebra_dic[router_name]['filename']='topo/zebra/zebra-'+router_name+'.conf'

        for node_struct in node_list:
            node_name=node_struct['name']
            if node_struct['type']=="BGP":
                router_name=node_struct['name']
                if router_bgp_dic.has_key(router_name)==False:
                    router_bgp_dic[router_name]={}
                    router_bgp_dic[router_name]['redistribute']=[]
                    router_bgp_dic[router_name]['router-id']=node_struct['router-id']
                    router_bgp_dic[router_name]['asn']=node_struct['asn']
                    router_bgp_dic[router_name]['neighbor']=[]
                    router_bgp_dic[router_name]['log file']='/tmp/'+router_name+'-bgpd.log'
                    router_bgp_dic[router_name]['filename']='topo/bgp/bgpd-'+router_name+'.conf'
                for ethi in node_struct['eth_n']:
                    ethi_link_ip_list=[]
                    for link_items in link_list:
                        if ethi in link_items:
                            ethi_link_ip_list=link_items
                            #important,avoid the left router link repeated
                            link_list.remove(link_items)
                            break
                    #find ip list refer to ethi
                    if len(ethi_link_ip_list)==2:
                        neighbor_node={}
                        ethi_link_ip_list.remove(ethi)#get other ip of two
                        neighbor_ip=ethi_link_ip_list[0]
                        for nb_node in node_list:
                            if neighbor_ip in nb_node['eth_n']:
                                #link to must not be host's gw
                                if nb_node['type']=='HOST' and nb_node['eth_n'][1]==neighbor_ip:
                                    continue
                                neighbor_node=nb_node
                                break
                        if neighbor_node!={}:
                            neighbor_node_name=neighbor_node['name']
                            #addlink between router and neighbor_node
                            #attention!must keep the order of ethn
                            if neighbor_node['type']=="HOST":
                                #gw='via '+re.findall(r'(.*)/.*',ethi)[0]
                                gw='via '+neighbor_node['eth_n'][1]
                                #print gw
                                self.addHost(neighbor_node['name'],ip=neighbor_node['eth_n'][0],defaultRoute=gw)
                                self.addLink(router_name,neighbor_node['name'])
                                router_zebra_dic[router_name]['ethn'].append(ethi)
                            elif neighbor_node['type']=="OSPF" or neighbor_node['type']=="BGP":
                                self.addLink(router_name,neighbor_node['name'])
                                router_zebra_dic[router_name]['ethn'].append(ethi)
                                router_zebra_dic[neighbor_node_name]['ethn'].append(neighbor_ip)
                            else:
                                print 'neighbor node type unknown'
                                #continue for next ethi
                                continue     
                            #add conf file item for BGP or OSPF router
                            if neighbor_node['type']=="BGP":
                                if router_bgp_dic.has_key(neighbor_node_name)==False:
                                    router_bgp_dic[neighbor_node_name]={}
                                    router_bgp_dic[neighbor_node_name]['router-id']=neighbor_node['router-id']
                                    router_bgp_dic[neighbor_node_name]['asn']=neighbor_node['asn']
                                    router_bgp_dic[neighbor_node_name]['neighbor']=[]
                                    router_bgp_dic[neighbor_node_name]['redistribute']=[]
                                    router_bgp_dic[neighbor_node_name]['log file']='/tmp/'+neighbor_node_name+'-bgpd.log'
                                    router_bgp_dic[neighbor_node_name]['filename']='topo/bgp/bgpd-'+neighbor_node_name+'.conf'
                                #1->2
                                dic={}
                                ip=re.findall(r'(.*)/.*',neighbor_ip)
                                if ip!=[]:
                                    dic['ip']=ip[0]
                                dic['remote-as']=neighbor_node['asn']
                                dic['timers']='5 5'
                                router_bgp_dic[router_name]['neighbor'].append(dic)
                                dic={}
                                ip=re.findall(r'(.*)/.*',ethi)
                                if ip!=[]:
                                    dic['ip']=ip[0]
                                dic['remote-as']=node_struct['asn']
                                dic['timers']='5 5'                          
                                router_bgp_dic[neighbor_node_name]['neighbor'].append(dic)
                            elif neighbor_node['type']=="OSPF":
                                #create ospf.conf for bgp router
                                if router_ospf_dic.has_key(router_name)==False:
                                    router_ospf_dic[router_name]={}
                                    router_ospf_dic[router_name]['router-id']=node_struct['router-id']
                                    router_ospf_dic[router_name]['network']=[]
                                    router_ospf_dic[router_name]['redistribute']=[]
                                    router_ospf_dic[router_name]['log file']='/tmp/'+router_name+'-ospfdd.log'
                                    router_ospf_dic[router_name]['filename']='topo/ospf/ospfd-'+router_name+'.conf'
                                #create ospf conf for neighbor ospf router
                                if router_ospf_dic.has_key(neighbor_node_name)==False:
                                    router_ospf_dic[neighbor_node_name]={}
                                    router_ospf_dic[neighbor_node_name]['router-id']=neighbor_node['router-id']
                                    router_ospf_dic[neighbor_node_name]['network']=[]
                                    router_ospf_dic[neighbor_node_name]['redistribute']=[]
                                    router_ospf_dic[neighbor_node_name]['log file']='/tmp/'+neighbor_node_name+'-ospfdd.log'
                                    router_ospf_dic[neighbor_node_name]['filename']='topo/ospf/ospfd-'+neighbor_node_name+'.conf'
                                 #bgp router link ospf router ,so redistribute ospf,etc.
                                if 'ospf' not in router_bgp_dic[router_name]['redistribute']:
                                    router_bgp_dic[router_name]['redistribute'].append('ospf')
                                if 'bgp' not in router_ospf_dic[router_name]['redistribute']:
                                    router_ospf_dic[router_name]['redistribute'].append('bgp')
                                dic={}
                                dic['ip']=ethi
                                dic['area']='0'   #TODO
                                router_ospf_dic[router_name]['network'].append(dic)
                                dic={}
                                dic['ip']=neighbor_ip
                                dic['area']='0'   #TODO
                                router_ospf_dic[neighbor_node_name]['network'].append(dic)
                            elif neighbor_node['type']=="HOST":
                                pass
                            else:
                                print "in ospf router to conf file never happen!"
                        else:
                            print router_name+" :can not find its neighbor"
                    elif len(ethi_link_ip_list)>2:
                        print router_name+' :can bgp routers be linked with L2 switch?'
                    elif len(ethi_link_ip_list)==0:
                        print router_name+':bgp can not find link,maybe all be added before'
                    else:
                        pass
            elif node_struct['type']=="OSPF":
                router_name=node_struct['name']
                if router_ospf_dic.has_key(router_name)==False:
                    router_ospf_dic[router_name]={}
                    router_ospf_dic[router_name]['router-id']=node_struct['router-id']
                    router_ospf_dic[router_name]['network']=[]
                    router_ospf_dic[router_name]['redistribute']=[]
                    router_ospf_dic[router_name]['log file']='/tmp/'+router_name+'-ospfdd.log'
                    router_ospf_dic[router_name]['filename']='topo/ospf/ospfd-'+router_name+'.conf'
                for ethi in node_struct['eth_n']:
                    ethi_link_ip_list=[]
                    for link_items in link_list:
                        if ethi in link_items:
                            ethi_link_ip_list=link_items
                            #important,avoid the left router link repeated
                            link_list.remove(link_items)
                            break
                    if len(ethi_link_ip_list)==2:
                        neighbor_node={}
                        ethi_link_ip_list.remove(ethi)#get other ip of two
                        neighbor_ip=ethi_link_ip_list[0]
                        for nb_node in node_list:
                            if neighbor_ip in nb_node['eth_n']:
                                if nb_node['type']=='HOST' and nb_node['eth_n'][1]==neighbor_ip:
                                    continue
                                neighbor_node=nb_node
                                break
                        if neighbor_node!={}:
                            neighbor_node_name=neighbor_node['name']
                            #addlink between router and neighbor_node
                            #attention!must keep the order of ethn
                            if neighbor_node['type']=="HOST":
                                #gw='via '+re.findall(r'(.*)/.*',ethi)[0]
                                gw='via '+neighbor_node['eth_n'][1]
                                #print gw
                                self.addHost(neighbor_node['name'],ip=neighbor_node['eth_n'][0],defaultRoute=gw)
                                self.addLink(router_name,neighbor_node['name'])
                                router_zebra_dic[router_name]['ethn'].append(ethi)
                            elif neighbor_node['type']=="OSPF" or neighbor_node['type']=="BGP":
                                self.addLink(router_name,neighbor_node['name'])
                                router_zebra_dic[router_name]['ethn'].append(ethi)
                                router_zebra_dic[neighbor_node_name]['ethn'].append(neighbor_ip)
                            else:
                                print 'neighbor node type unknown'
                                #continue for next ethi
                                continue  
                            if neighbor_node['type']=="OSPF":
                                if router_ospf_dic.has_key(neighbor_node_name)==False:
                                    router_ospf_dic[neighbor_node_name]={}
                                    router_ospf_dic[neighbor_node_name]['router-id']=neighbor_node['router-id']
                                    router_ospf_dic[neighbor_node_name]['network']=[]
                                    router_ospf_dic[neighbor_node_name]['redistribute']=[]
                                    router_ospf_dic[neighbor_node_name]['log file']='/tmp/'+neighbor_node_name+'-ospfdd.log'
                                    router_ospf_dic[neighbor_node_name]['filename']='topo/ospf/ospfd-'+neighbor_node_name+'.conf'
                                dic={}
                                dic['ip']=ethi
                                dic['area']='0'   #TODO
                                router_ospf_dic[router_name]['network'].append(dic)
                                dic={}
                                dic['ip']=neighbor_ip
                                dic['area']='0'   #TODO
                                router_ospf_dic[neighbor_node_name]['network'].append(dic)
                            elif neighbor_node['type']=="BGP":
                                if router_ospf_dic.has_key(neighbor_node_name)==False:
                                    router_ospf_dic[neighbor_node_name]={}
                                    router_ospf_dic[neighbor_node_name]['router-id']=neighbor_node['router-id']
                                    router_ospf_dic[neighbor_node_name]['network']=[]
                                    router_ospf_dic[neighbor_node_name]['redistribute']=[]
                                    router_ospf_dic[neighbor_node_name]['log file']='/tmp/'+neighbor_node_name+'-ospfdd.log'
                                    router_ospf_dic[neighbor_node_name]['filename']='topo/ospf/ospfd-'+neighbor_node_name+'.conf'
                                if router_bgp_dic.has_key(neighbor_node_name)==False:
                                    router_bgp_dic[neighbor_node_name]={}
                                    router_bgp_dic[neighbor_node_name]['router-id']=neighbor_node['router-id']
                                    router_bgp_dic[neighbor_node_name]['asn']=neighbor_node['asn']
                                    router_bgp_dic[neighbor_node_name]['neighbor']=[]
                                    router_bgp_dic[neighbor_node_name]['redistribute']=[]
                                    router_bgp_dic[neighbor_node_name]['log file']='/tmp/'+neighbor_node_name+'-bgpd.log'
                                    router_bgp_dic[neighbor_node_name]['filename']='topo/bgp/bgpd-'+neighbor_node_name+'.conf'
                                #1->2
                                if 'ospf' not in router_bgp_dic[neighbor_node_name]['redistribute']:
                                    router_bgp_dic[neighbor_node_name]['redistribute'].append('ospf')
                                if 'bgp' not in router_ospf_dic[neighbor_node_name]['redistribute']:
                                    router_ospf_dic[neighbor_node_name]['redistribute'].append('bgp')
                                dic={}
                                dic['ip']=ethi
                                dic['area']='0'   #TODO
                                router_ospf_dic[router_name]['network'].append(dic)
                                dic={}
                                dic['ip']=neighbor_ip
                                dic['area']='0'   #TODO
                                router_ospf_dic[neighbor_node_name]['network'].append(dic)
                            elif neighbor_node['type']=="HOST":
                                #if ospf router link to host,not add network to ospf conf
                                pass
                                # dic={}
                                # dic['ip']=ethi
                                # dic['area']=0   #TODO
                                # router_ospf_dic[router_name]['network'].append(dic)
                            else:
                                print "in ospf router to conf file never happen!"
                    #for ospf routers linked with switch
                    if len(ethi_link_ip_list)>2:
                        #if the ospf router linked by switch,add this interface to network?
                        dic={}
                        dic['ip']=ethi
                        dic['area']='0'   #TODO
                        router_ospf_dic[router_name]['network'].append(dic)
                        ethi_link_ip_list.remove(ethi)
                        switch_name='s'+str(switch_index)
                        switch_index=switch_index+1
                        self.addSwitch(switch_name,cls=OVSKernelSwitch)
                        self.addLink(router_name,switch_name)
                        router_zebra_dic[router_name]['ethn'].append(ethi)
                        for link_ip in ethi_link_ip_list:
                            linke_to_switch_node={}
                            #TODO:maybe not need loop from begin
                            for nb_node in node_list:
                                if link_ip in nb_node['eth_n']:
                                    if nb_node['type']=='HOST' and nb_node['eth_n'][1]==link_ip:
                                        continue
                                    linke_to_switch_node=nb_node
                                    break
                            if linke_to_switch_node!={}:
                                linke_to_switch_node_name=linke_to_switch_node['name']
                                if linke_to_switch_node['type']=="HOST":
                                    #gw='via '+re.findall(r'(.*)/.*',ethi)[0]
                                    #if host link to more than one router by switch ,must tell gw
                                    gw='via '+linke_to_switch_node['eth_n'][1]
                                    self.addHost(linke_to_switch_node['name'],ip=link_ip,defaultRoute=gw)
                                    self.addLink(switch_name,linke_to_switch_node_name)
                                elif linke_to_switch_node['type']=="OSPF":
                                    self.addLink(switch_name,linke_to_switch_node_name)
                                    router_zebra_dic[linke_to_switch_node_name]['ethn'].append(link_ip)
                                    if router_ospf_dic.has_key(linke_to_switch_node_name)==False:
                                        router_ospf_dic[linke_to_switch_node_name]={}
                                        router_ospf_dic[linke_to_switch_node_name]['router-id']=linke_to_switch_node['router-id']
                                        router_ospf_dic[linke_to_switch_node_name]['network']=[]
                                        router_ospf_dic[linke_to_switch_node_name]['redistribute']=[]
                                        router_ospf_dic[linke_to_switch_node_name]['log file']='/tmp/'+linke_to_switch_node_name+'-ospfdd.log'
                                        router_ospf_dic[linke_to_switch_node_name]['filename']='topo/ospf/ospfd-'+linke_to_switch_node_name+'.conf'
                                    #ospf router linked by switch,add nework?
                                    dic={}
                                    dic['ip']=link_ip
                                    dic['area']='0'   #TODO
                                    router_ospf_dic[linke_to_switch_node_name]['network'].append(dic)
                                elif linke_to_switch_node['type']=="BGP":
                                    print "can BGP link to ospf with a L2 switch?"
                                else:
                                    print "OSPF link to unknow node by a switch"
                            else:
                                print "ospf router can not find the node link in same switch"
                    if len(ethi_link_ip_list)==0:
                        print 'ospf can not find link,maybe all be added before'
            elif node_struct['type']=="HOST":
                host_name=node_struct['name']
                host_ip=node_struct['eth_n'][0]
                ethi_link_ip_list=[]
                for link_items in link_list:
                    if host_ip in link_items:
                        ethi_link_ip_list=link_items
                        #important,avoid the left router link repeated
                        link_list.remove(link_items)
                        break
                if len(ethi_link_ip_list)==2:
                    neighbor_node={}
                    ethi_link_ip_list.remove(host_ip)#get other ip of two
                    neighbor_ip=ethi_link_ip_list[0]
                    for nb_node in node_list:
                        if neighbor_ip in nb_node['eth_n']:
                            if nb_node['type']=='HOST' and nb_node['eth_n'][1]==neighbor_ip:
                                continue
                            neighbor_node=nb_node
                            break
                    if neighbor_node!={}:
                        neighbor_node_name=neighbor_node['name']
                        if neighbor_node['type']=="HOST":
                            print 'can '+host_name+' link to host '+neighbor_node_name+"?"
                        elif neighbor_node['type']=="OSPF" or neighbor_node['type']=="BGP":
                            gw='via '+node_struct['eth_n'][1]
                            self.addHost(host_name,ip=host_ip,defaultRoute=gw)
                            self.addLink(host_name,neighbor_node['name'])
                            router_zebra_dic[neighbor_node_name]['ethn'].append(neighbor_ip)
                        else:
                            print host_name+'neighbor node type unknown'
                            #continue for next node
                            continue  
                elif len(ethi_link_ip_list)>2:
                    #this host link node by a switch
                    gw='via '+node_struct['eth_n'][1]
                    self.addHost(host_name,ip=host_ip,defaultRoute=gw)
                    switch_name='s'+str(switch_index)
                    switch_index=switch_index+1
                    self.addSwitch(switch_name,cls=OVSKernelSwitch)
                    self.addLink(host_name,switch_name)
                    ethi_link_ip_list.remove(host_ip)
                    for link_ip in ethi_link_ip_list:
                        linke_to_switch_node={}
                        #TODO:maybe not need loop from begin
                        for nb_node in node_list:
                            if link_ip in nb_node['eth_n']:
                                if nb_node['type']=='HOST' and nb_node['eth_n'][1]==link_ip:
                                    continue
                                linke_to_switch_node=nb_node
                                break
                        if linke_to_switch_node!={}:
                            linke_to_switch_node_name=linke_to_switch_node['name']
                            if linke_to_switch_node['type']=="HOST":
                                gw='via '+linke_to_switch_node['eth_n'][1]
                                self.addHost(linke_to_switch_node_name,ip=host_ip,defaultRoute=gw)
                                self.addLink(switch_name,linke_to_switch_node_name)
                            elif linke_to_switch_node['type']=="OSPF":
                                self.addLink(switch_name,linke_to_switch_node_name)
                                router_zebra_dic[linke_to_switch_node_name]['ethn'].append(link_ip)
                                if router_ospf_dic.has_key(linke_to_switch_node_name)==False:
                                    router_ospf_dic[linke_to_switch_node_name]={}
                                    router_ospf_dic[linke_to_switch_node_name]['router-id']=linke_to_switch_node['router-id']
                                    router_ospf_dic[linke_to_switch_node_name]['network']=[]
                                    router_ospf_dic[linke_to_switch_node_name]['redistribute']=[]
                                    router_ospf_dic[linke_to_switch_node_name]['log file']='/tmp/'+linke_to_switch_node_name+'-ospfdd.log'
                                    router_ospf_dic[linke_to_switch_node_name]['filename']='topo/ospf/ospfd-'+linke_to_switch_node_name+'.conf'
                                #ospf router linked by switch,add nework?
                                dic={}
                                dic['ip']=link_ip
                                dic['area']='0'   #TODO
                                router_ospf_dic[linke_to_switch_node_name]['network'].append(dic)
                            elif linke_to_switch_node['type']=="BGP":
                                print host_name+" :can BGP link to ospf with a L2 switch?"
                                # self.addLink(switch_name,linke_to_switch_node_name)
                                # router_zebra_dic[linke_to_switch_node_name]['ethn'].append(link_ip)
                            else:
                                print host_name+' :neighbor node type unknown'
                elif len(ethi_link_ip_list)==0:
                    print host_name+' :can not find link,maybe be linked by before'
                else:
                    pass
            else:
                print node_name+' :unknow this node type'
        #create conf file
        for k in router_bgp_dic:
            f=open(router_bgp_dic[k]['filename'],'w')
            f.write('hostname %s\n' % k)
            f.write('password en\nenable password en\n\n')
            f.write('router bgp %s\n' % router_bgp_dic[k]['asn'])
            f.write('  bgp router-id %s\n' % router_bgp_dic[k]['router-id'])
            f.write('  redistribute connected\n')
            for redistribute in router_bgp_dic[k]['redistribute']:
                f.write('  redistribute %s\n' % redistribute)
            for nb in router_bgp_dic[k]['neighbor']:
                f.write('  neighbor %s remote-as %s\n' % (nb['ip'],nb['remote-as']))
                f.write('  neighbor %s timers %s\n' % (nb['ip'],nb['timers']))
            f.write('log file %s\n\n' % router_bgp_dic[k]['log file'])
            f.write('log stdout')
            f.close()
        for k in router_ospf_dic:
            f=open(router_ospf_dic[k]['filename'],'w')
            f.write('hostname %s\n' % k)
            f.write('password en\n\n')
            f.write('router ospf\n')
            f.write('  ospf router-id %s\n' % router_ospf_dic[k]['router-id'])  
            f.write('  redistribute connected\n')
            for redistribute in router_ospf_dic[k]['redistribute']:
                f.write('  redistribute %s\n' % redistribute)
            for network in router_ospf_dic[k]['network']:
                f.write('  network %s area %s\n' % (network['ip'], network['area']))
            f.write('log file %s\n\n' % router_ospf_dic[k]['log file'])
            f.write('log stdout')
            f.close()
        for k in router_zebra_dic:
            f=open(router_zebra_dic[k]['filename'],'w')
            f.write('hostname %s\n' % k)
            f.write('password en\n\n')
            f.write('interface lo\n  ip address 127.0.0.1/8\n')
            i=1
            for ethn in router_zebra_dic[k]['ethn']:
                f.write('interface %s-eth%d\n' % (k,i))
                f.write('  ip address %s\n\n' % ethn)
                i=i+1
            f.write('log file %s' % router_zebra_dic[k]['log file'])
            f.close()
        return
# Start the routing daemons
# When a I2RS daemon is ready add it to the routers you want it to run, probably run:
# router.cmd("/usr/lib/quagga/i2rsd -f conf/i2rsd-%s.conf -d -i /tmp/i2rsd-%s.pid > logs/%s-i2rsd-stdout 2>&1" % (router.name, router.name, router.name))
# router.waitOutput()
def IsSubString(SubStrList,Str): 
 ''''' 
 #判断字符串Str是否包含序列SubStrList中的每一个子字符串 
 #>>>SubStrList=['F','EMS','txt'] 
 #>>>Str='F06925EMS91.txt' 
 #>>>IsSubString(SubStrList,Str)#return True (or False) 
 '''
 flag=True
 for substr in SubStrList: 
  if not(substr in Str): 
   flag=False
 return flag 
#~ #---------------------------------------------------------------------- 
def GetFileList(FindPath,FlagStr=[]): 
 ''''' 
 #获取目录中指定的文件名 
 #>>>FlagStr=['F','EMS','txt'] #要求文件名称中包含这些字符 
 #>>>FileList=GetFileList(FindPath,FlagStr) # 
 '''
 import os 
 FileList=[] 
 FileNames=os.listdir(FindPath) 
 if (len(FileNames)>0): 
  for fn in FileNames: 
   if (len(FlagStr)>0): 
    #返回指定类型的文件名 
    if (IsSubString(FlagStr,fn)): 
     fullfilename=os.path.join(FindPath,fn) 
     FileList.append(fullfilename) 
   else: 
    #默认直接返回所有文件名 
    fullfilename=os.path.join(FindPath,fn) 
    FileList.append(fullfilename) 
 #对文件名排序 
 if (len(FileList)>0): 
  FileList.sort() 
 return FileList

def startRouting(router):
    if GetFileList('./topo/zebra',FlagStr=[router.name])!=[]: 
        router.cmd("/usr/lib/quagga/zebra -f topo/zebra/zebra-%s.conf -d -i /tmp/zebra-%s.pid > logs/%s-zebra-stdout 2>&1" % (router.name, router.name, router.name))
        router.waitOutput()
        print router.name+' configure zebra...'
    else:
        log("WARNING: No routing deamon configured for %s." % (router.name))
    if GetFileList('./topo/ospf',FlagStr=[router.name])!=[]:
        print router.name+' configure ospf...'
        router.cmd("/usr/lib/quagga/ospfd -f topo/ospf/ospfd-%s.conf -d -i /tmp/ospfd-%s.pid > logs/%s-ospfd-stdout 2>&1" % (router.name, router.name, router.name), shell=True)
        router.waitOutput()
    if GetFileList('./topo/bgp',FlagStr=[router.name])!=[]:
        router.cmd("/usr/lib/quagga/bgpd -f topo/bgp/bgpd-%s.conf -d -i /tmp/bgpd-%s.pid > logs/%s-bgpd-stdout 2>&1" % (router.name, router.name, router.name), shell=True)
        router.waitOutput()
        print router.name+' configure bgp...'
    return

def main():
    os.system("rm -f /tmp/r*.log /tmp/r*.pid logs/*")
    os.system("mn -c >/dev/null 2>&1")
    os.system("killall -9 zebra bgpd ospfd > /dev/null 2>&1")

    net = Mininet(topo=SimpleTopo(), switch=Router,link=TCLink)
    net.start()
    for router in net.switches:
        #print "*********"+router.name
        router.cmd("sysctl -w net.ipv4.ip_forward=1")
        router.waitOutput()

    log("Waiting %d seconds for sysctl changes to take effect..."
        % args.sleep)
    sleep(args.sleep)

    # # initialize routing daemons
    for router in net.switches:
        startRouting(router)

#     # set hosts IP and gateways
    # for host in net.hosts:
#        using "ip cmd" leaves 10.0.0.x/8 ip on the interface of the hosts and 10.0.0.0/8 on the routing table
#        host.cmd("ip a add %s dev %s-eth0" % (getIP(host.name), host.name))
#        host.cmd("ip r add default via %s" % (getGateway(host.name)))
        # host.cmd("ifconfig %s-eth0 %s" % (host.name, getIP(host.name)))
        # host.cmd("route add default gw %s" % (getGateway(host.name)))

    CLI(net)
    net.stop()
    os.system("killall -9 zebra bgpd ospfd")

if __name__ == "__main__":
    main()