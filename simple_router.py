
# ex : sudo python hw3_net.py -n 6

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import RemoteController, OVSSwitch
import sys, getopt


def MininetTopo(argv):

    net = Mininet()

    info("Create host nodes.\n")
    h1 = net.addHost('h1',ip="10.0.1.10/24",mac="00:00:00:00:00:01")
    h2 = net.addHost('h2',ip="10.0.2.10/24",mac="00:00:00:00:00:02")

    info("Create switch node.\n")
    s1 = net.addSwitch('s1',switch = OVSSwitch,failMode = 'secure',protocols = 'OpenFlow13')
    s2 = net.addSwitch('s2',switch = OVSSwitch,failMode = 'secure',protocols = 'OpenFlow13')

    info("Create router node.\n")
    r1 = net.addHost('r1')
 
    info("Create Links.\n")
    net.addLink(r1,s1)
    net.addLink(r1,s2)
    net.addLink(h1,s1)
    net.addLink(h2,s2)

    info("Create Controller.\n")
    net.addController(name = 'c0',controller = RemoteController,ip = '127.0.0.1',port = 6633)

    info("Build and start network.\n")
    net.build()
    net.start()

    r1.cmd("ifconfig r1-eth0 0")
    r1.cmd("ifconfig r1-eth1 0")
    r1.cmd("ifconfig r1-eth0 hw ether 00:00:00:00:01:01")
    r1.cmd("ifconfig r1-eth1 hw ether 00:00:00:00:01:02")
    r1.cmd("ip addr add 10.0.1.1/24 brd + dev r1-eth0")
    r1.cmd("ip addr add 10.0.2.1/24 brd + dev r1-eth1")
    r1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    h1.cmd("ip route add default via 10.0.1.1")
    h2.cmd("ip route add default via 10.0.2.1")
    """
    s1.cmd("ovs-ofctl add-flow s1 priority=1,arp,actions=flood")
    s1.cmd("ovs-ofctl add-flow s1 priority=65535,ip,dl_dst=00:00:00:00:01:01,actions=output:1")
    s1.cmd("ovs-ofctl add-flow s1 priority=10,ip,nw_dst=10.0.1.0/24,actions=output:2")
    s2.cmd("ovs-ofctl add-flow s2 priority=1,arp,actions=flood")
    s2.cmd("ovs-ofctl add-flow s2 priority=65535,ip,dl_dst=00:00:00:00:01:02,actions=output:1")
    s2.cmd("ovs-ofctl add-flow s2 priority=10,ip,nw_dst=10.0.2.0/24,actions=output:2")
    """

    info("Run mininet CLI.\n")
    CLI(net)

if __name__ == '__main__':
    setLogLevel('info')
    MininetTopo(sys.argv[1:])
