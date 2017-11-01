#!/usr/bin/env python

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

        router=self.addSwitch('r1',cls=OVSKernelSwitch)
        routers.append(router)

        router21=self.addSwitch('r010_21')
        routers.append(router21)
        self.addLink('r1','r010_21')  

        router22=self.addSwitch('r010_22')
        routers.append(router22)
        self.addLink('r1','r010_22') 


        host21 = self.addHost('h010_21',ip='10.4.8.2/24',defaultRoute='via 10.4.8.1')
        hosts.append(host21)
        host22 = self.addHost('h010_22',ip='10.4.9.2/24',defaultRoute='via 10.4.9.1')
        hosts.append(host22)
        self.addLink('r010_21','h010_21')
        self.addLink('r010_22','h010_22')

        host1 = self.addHost('h1')
        #hosts.append(host1)
        self.addLink('r1',host1)
        host2 = self.addHost('h2')
        #hosts.append(host2)
        self.addLink('r1',host2)
        host3=self.addHost('h3',ip='10.255.0.2/28',defaultRoute='10.255.0.18')
        self.addLink('r1','h3')
            # create and attach one host per router
        # for i in xrange(num_router):
        #         router = 'r010_%d' % (i+1)
        #         for j in xrange(num_hosts_per_router):
        #             hostname = 'h010_%d%d' % (i+1, j+1)
        #             host = self.addHost(hostname)
        #             hosts.append(host)
        #             self.addLink(router, host)

            #routers AS100 and AS200 and BGP links

        return
# Start the routing daemons
# When a I2RS daemon is ready add it to the routers you want it to run, probably run:
# router.cmd("/usr/lib/quagga/i2rsd -f conf/i2rsd-%s.conf -d -i /tmp/i2rsd-%s.pid > logs/%s-i2rsd-stdout 2>&1" % (router.name, router.name, router.name))
# router.waitOutput()
def startRouting(router):
    if router.name=='r010_2m':
        return
    flag=-1
    flag=router.name.find('r010_')
    if flag!=-1:
        router.cmd("/usr/lib/quagga/zebra -f test/zebra/zebra-%s.conf -d -i /tmp/zebra-%s.pid > logs/%s-zebra-stdout 2>&1" % (router.name, router.name, router.name))
        router.waitOutput()
        router.cmd("/usr/lib/quagga/ospfd -f test/ospf/ospfd-%s.conf -d -i /tmp/ospfd-%s.pid > logs/%s-ospfd-stdout 2>&1" % (router.name, router.name, router.name), shell=True)
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
    # net.__init__()
    # r1=net.addSwitch('r1',failMode='standalone')
    # h1=net.addHost('h1', cls=Host, ip='10.0.0.4', defaultRoute=None)
    # h2=net.addHost('h4', cls=Host, ip='10.0.0.1', defaultRoute=None)
    # net.addLink(r1,h1) 
    # net.addLink(r1,h2)
    net.start()
    # for controller in net.controllers:
    #     controller.start()
    #net.get('r1').start([])
    #net.start()
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