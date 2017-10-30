#!/usr/bin/env python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import lg, info, setLogLevel
from mininet.util import dumpNodeConnections, quietRun, moveIntf
from mininet.cli import CLI
from mininet.node import Switch, OVSKernelSwitch
from mininet.node import CPULimitedHost
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
        return

    def start(self, controllers):
        pass

    def stop(self):
        self.deleteIntfs()

    def log(self, s, col="magenta"):
        print T.colored(s, col)

class SimpleTopo(Topo):
    def __init__(self):
        # Add default members to class.
        super(SimpleTopo, self ).__init__()
        num_hosts_per_router = 1 # The topology has one host per router
        global routers
        routers = []
        hosts = []

        #AS10
        #num_router = 5
        # create routers
        # for i in xrange(num_router):
        #     router = self.addSwitch('r010_%d' % (i+1))
        #     routers.append(router)

        # # add link between routers
        # for i in xrange(num_router-1):
        #     self.addLink('r010_%d' % (i+1), 'r010_%d' % (i+2))
        # self.addLink('r010_5', 'r010_1')
        # hostname r010_2
        # password en

        # router ospf
        #   ospf router-id 10.10.0.2
        #   redistribute connected
        #   network 10.10.0.2/32 area 0
        #   network 10.255.0.2/30 area 0
        #   network 10.255.0.5/30 area 0

        # log file /tmp/r010_2-ospfdd.log

        # !
        # log stdout
        # hostname r010_3
        # password en
        # enable password en


        # !

        # interface lo
        #   ip address 127.0.0.1/8
        #   ip address 10.10.0.3/32

        # interface r010_3-eth1
        #   ip address 10.255.0.6/30

        # interface r010_3-eth2
        #   ip address 10.255.0.9/30

        # interface r010_3-eth3
        #   ip address 10.3.0.1/24

        # log file /tmp/r010_3.log
        router=self.addSwitch('r010_1')
        routers.append(router)

        def create_tree(router,router_eth1,level):
            global wire_number,host_number,router_id,routers
            if level<=1:
                host_number=host_number+1
                hostname = 'h010_%d' % host_number
                host_ip='10.4.%d.2/24' % host_number
                host_gw='via 10.4.%d.1' % host_number
                host = self.addHost(hostname, ip=host_ip, defaultRoute = host_gw)
                #hosts.append(host)
                self.addLink(router, host)
                router_id=router_id+1
                ospf_file='tree/ospf/ospfd-%s.conf' % router
                f=open(ospf_file,'w')
                f.write('hostname %s\n' % router)
                f.write('password en\n\n')
                f.write('router ospf\n')
                f.write('  ospf router-id 10.10.0.%d\n' % router_id)
                f.write('  redistribute connected\n')
                f.write('  network 10.10.0.%d/32 area 0\n' % router_id)#lo
                f.write('  network %s/30 area 0\n\n' % router_eth1)#eth1
                f.write('log file /tmp/%s-ospfdd.log\n' % router)
                f.write('log stdout\n')
                f.close()
                zebra_file='tree/zebra/zebra-%s.conf' % router
                f=open(zebra_file,'w')
                f.write('hostname %s\npassword en\nenable password en\n\n' % router)
                f.write('interface lo\n')
                f.write('  ip address 127.0.0.1/8\n  ip address 10.10.0.%d/32\n\n' % router_id)
                f.write('interface %s-eth1\n' % router)
                f.write('  ip address %s/30\n\n' % router_eth1)
                f.write('interface %s-eth2\n' % router)
                f.write('  ip address 10.4.%d.1/24\n\n' % host_number)#end link to host
                f.write('log file /tmp/%s.log' % router)
                f.close()
            else:
                router_id=router_id+1
                R_left = self.addSwitch('r010_%d' % (wire_number+1))
                R_left_name='r010_%d' % (wire_number+1)
                routers.append(R_left)
                R_right = self.addSwitch('r010_%d' % (wire_number+2))
                R_right_name='r010_%d' % (wire_number+2)
                routers.append(R_right)
                self.addLink(router, R_left)
                self.addLink(router, R_right)
                wire_number=wire_number+1
                router_eth2_number=(10<<24)+(255<<16)+(wire_number<<2)+1
                router_eth2=socket.inet_ntoa(struct.pack('!L', router_eth2_number))
                R_left_eth1_number=(10<<24)+(255<<16)+(wire_number<<2)+2
                R_left_eth1=socket.inet_ntoa(struct.pack('!L', R_left_eth1_number))
                wire_number=wire_number+1
                router_eth3_number=(10<<24)+(255<<16)+(wire_number<<2)+2
                router_eth3=socket.inet_ntoa(struct.pack('!L', router_eth3_number))
                R_right_eth1_number=(10<<24)+(255<<16)+(wire_number<<2)+1
                R_right_eth1=socket.inet_ntoa(struct.pack('!L', R_right_eth1_number))
                ospf_file='tree/ospf/ospfd-%s.conf' % router
                f=open(ospf_file,'w')
                f.write('hostname %s\n' % router)
                f.write('password en\n\n')
                f.write('router ospf\n')
                f.write('  ospf router-id 10.10.0.%d\n' % router_id)
                f.write('  redistribute connected\n')
                if router_id==1:
                    f.write('  redistribute bgp\n')
                f.write('  network 10.10.0.%d/32 area 0\n' % router_id)#lo
                if router_id!=1:
                    f.write('  network %s/30 area 0\n' % router_eth1)#eth1
                f.write('  network %s/30 area 0\n' % router_eth2)#eth2
                f.write('  network %s/30 area 0\n\n' % router_eth3)#eth3 
                f.write('log file /tmp/%s-ospfdd.log\n' % router)
                f.write('log stdout\n')
                f.close()
                zebra_file='tree/zebra/zebra-%s.conf' % router
                f=open(zebra_file,'w')
                if router_id!=1:
                    f.write('hostname %s\npassword en\nenable password en\n\n' % router)
                    f.write('interface lo\n')
                    f.write('  ip address 127.0.0.1/8\nip address 10.10.0.%d/32\n\n' % router_id)
                    f.write('interface %s-eth1\n' % router)
                    f.write('  ip address %s/30\n\n' % router_eth1)
                    f.write('interface %s-eth2\n' % router)
                    f.write('  ip address %s/30\n\n' % router_eth2)
                    f.write('interface %s-eth3\n' % router)
                    f.write('  ip address %s/30\n\n' % router_eth3)
                    f.write('log file /tmp/%s.log' % router)
                else:
                    f.write('hostname %s\npassword en\nenable password en\n\n' % router)
                    f.write('interface lo\n')
                    f.write('  ip address 127.0.0.1/8\n  ip address 10.10.0.%d/32\n\n' % router_id)
                    f.write('interface %s-eth1\n' % router)
                    f.write('  ip address %s/30\n\n'  % router_eth2)
                    f.write('interface %s-eth2\n' % router)
                    f.write('  ip address %s/30\n\n'  % router_eth3)
                    f.write('interface %s-eth3\n' % router)
                    f.write('  ip address 10.4.1.1/24\n\n')
                    f.write('interface %s-eth4\n' % router)
                    f.write('  ip address 10.0.0.1/30\n\n')                   #link r100_1 10.0.0.2/30
                    f.write('interface %s-eth5\n' % router)
                    f.write('  ip address 10.0.0.5/30\n\n')                   #link r200_1 10.0.0.6/30
                    f.write('log file /tmp/%s.log' % router)
                f.close()
                level=level-1
                create_tree(R_left_name,R_left_eth1,level)
                create_tree(R_right_name,R_right_eth1,level)
        global wire_number,host_number,router_id
        level=3
        wire_number=1
        host_number=1
        router_id=0
        router_eth1=''
        router='r010_1'
        create_tree(router,router_eth1,level)
        hostname = 'h010_1'
        host = self.addHost(hostname,ip='10.4.1.2/24', defaultRoute ='via 10.4.1.1')#router eth3
        self.addLink(router, host)
            # create and attach one host per router
        # for i in xrange(num_router):
        #         router = 'r010_%d' % (i+1)
        #         for j in xrange(num_hosts_per_router):
        #             hostname = 'h010_%d%d' % (i+1, j+1)
        #             host = self.addHost(hostname)
        #             hosts.append(host)
        #             self.addLink(router, host)

            #routers AS100 and AS200 and BGP links
        router = self.addSwitch('r100_1')
        routers.append(router)
        router = self.addSwitch('r200_1')
        routers.append(router)
        self.addLink('r010_1', 'r100_1',bw=0.001)                               #r010_1 eth4------r100_1 eth1
        self.addLink('r010_1', 'r200_1',bw=0.001)                               #r010_1 eth5------r200_1 eth1
        self.addLink('r100_1', 'r200_1',bw=0.001)
        
        #AS100 hosts
        router = 'r100_1'
        for j in xrange(num_hosts_per_router):
            hostname = 'h100_1%d' % (j+1)
            host = self.addHost(hostname,ip='100.1.0.2/24',defaultRoute='via 100.1.0.1')
            hosts.append(host)
            self.addLink(router, host)

        #AS200 hosts
        router = 'r200_1'
        for j in xrange(num_hosts_per_router):
            hostname = 'h200_1%d' % (j+1)
            host = self.addHost(hostname,ip='200.1.0.2/24',defaultRoute='via 200.1.0.1')
            hosts.append(host)
            self.addLink(router, host)
        return

# Define host IP
def getIP(hostname):
    if hostname == "h010_11":
        ip = '10.1.0.2/24'
    elif hostname == "h010_21":
        ip = '10.2.0.2/24'
    elif hostname == "h010_31":
        ip = '10.3.0.2/24'
    elif hostname == "h010_41":
        ip = '10.4.0.2/24'
    elif hostname == "h010_51":
        ip = '10.5.0.2/24'
    elif hostname == "h100_11":
        ip = '100.1.0.2/24'
    elif hostname == "h200_11":
        ip = '200.1.0.2/24'
    else:
        log("WARNING: No IP was set for %s. Your netowork will probably not work correctly." % hostname)
        ip = ''
    return ip

# Define host Gateway
def getGateway(hostname):
    if hostname == "h010_11":
        gw = '10.1.0.1'
    elif hostname == "h010_21":
        gw = '10.2.0.1'
    elif hostname == "h010_31":
        gw = '10.3.0.1'
    elif hostname == "h010_41":
        gw = '10.4.0.1'
    elif hostname == "h010_51":
        gw = '10.5.0.1'
    elif hostname == "h100_11":
        gw = '100.1.0.1'
    elif hostname == "h200_11":
        gw = '200.1.0.1'
    else:
        gw = ''
    return gw

# Start the routing daemons
# When a I2RS daemon is ready add it to the routers you want it to run, probably run:
# router.cmd("/usr/lib/quagga/i2rsd -f conf/i2rsd-%s.conf -d -i /tmp/i2rsd-%s.pid > logs/%s-i2rsd-stdout 2>&1" % (router.name, router.name, router.name))
# router.waitOutput()
def startRouting(router):
    flag=-1
    flag=router.name.find('r010_')
    if router.name == "r100_1":
        router.cmd("/usr/lib/quagga/zebra -f conf/zebra-%s.conf -d -i /tmp/zebra-%s.pid > logs/%s-zebra-stdout 2>&1" % (router.name, router.name, router.name))
        router.waitOutput()
        router.cmd("/usr/lib/quagga/bgpd -f conf/bgpd-%s.conf -d -i /tmp/bgpd-%s.pid > logs/%s-bgpd-stdout 2>&1" % (router.name, router.name, router.name), shell=True)
        router.waitOutput()
        log("Starting zebra and bgpd on %s" % router.name)
    elif router.name == "r200_1":
        router.cmd("/usr/lib/quagga/zebra -f conf/zebra-%s.conf -d -i /tmp/zebra-%s.pid > logs/%s-zebra-stdout 2>&1" % (router.name, router.name, router.name))
        router.waitOutput()
        router.cmd("/usr/lib/quagga/bgpd -f conf/bgpd-%s.conf -d -i /tmp/bgpd-%s.pid > logs/%s-bgpd-stdout 2>&1" % (router.name, router.name, router.name), shell=True)
        router.waitOutput()
        log("Starting zebra and bgpd on %s" % router.name)
    elif router.name == "r010_1":
        router.cmd("/usr/lib/quagga/zebra -f tree/zebra/zebra-%s.conf -d -i /tmp/zebra-%s.pid > logs/%s-zebra-stdout 2>&1" % (router.name, router.name, router.name))
        router.waitOutput()
        router.cmd("/usr/lib/quagga/ospfd -f tree/ospf/ospfd-%s.conf -d -i /tmp/ospfd-%s.pid > logs/%s-ospfd-stdout 2>&1" % (router.name, router.name, router.name), shell=True)
        router.waitOutput()
        router.cmd("/usr/lib/quagga/bgpd -f conf/bgpd-%s.conf -d -i /tmp/bgpd-%s.pid > logs/%s-bgpd-stdout 2>&1" % (router.name, router.name, router.name), shell=True)
        router.waitOutput()
        log("Starting zebra and ospfd and bgpd on %s" % router.name)
    elif flag!=-1:
        router.cmd("/usr/lib/quagga/zebra -f tree/zebra/zebra-%s.conf -d -i /tmp/zebra-%s.pid > logs/%s-zebra-stdout 2>&1" % (router.name, router.name, router.name))
        router.waitOutput()
        router.cmd("/usr/lib/quagga/ospfd -f tree/ospf/ospfd-%s.conf -d -i /tmp/ospfd-%s.pid > logs/%s-ospfd-stdout 2>&1" % (router.name, router.name, router.name), shell=True)
        router.waitOutput()
        log("Starting zebra and ospfd on %s" % router.name)
    else:
        log("WARNING: No routing deamon configured for %s." % (router.name))
    return

def main():
    os.system("rm -f /tmp/r*.log /tmp/r*.pid logs/*")
    os.system("mn -c >/dev/null 2>&1")
    os.system("killall -9 zebra bgpd ospfd > /dev/null 2>&1")

    net = Mininet(topo=SimpleTopo(), switch=Router,link=TCLink)
    net.start()
    for router in net.switches:
        print "*********"+router.name
        router.cmd("sysctl -w net.ipv4.ip_forward=1")
        router.waitOutput()

    log("Waiting %d seconds for sysctl changes to take effect..."
        % args.sleep)
    sleep(args.sleep)

    # initialize routing daemons
    for router in net.switches:
        startRouting(router)

#     # set hosts IP and gateways
    for host in net.hosts:
#        using "ip cmd" leaves 10.0.0.x/8 ip on the interface of the hosts and 10.0.0.0/8 on the routing table
#        host.cmd("ip a add %s dev %s-eth0" % (getIP(host.name), host.name))
#        host.cmd("ip r add default via %s" % (getGateway(host.name)))
        host.cmd("ifconfig %s-eth0 %s" % (host.name, getIP(host.name)))
        host.cmd("route add default gw %s" % (getGateway(host.name)))

    CLI(net)
    net.stop()
    os.system("killall -9 zebra bgpd ospfd")

if __name__ == "__main__":
    main()