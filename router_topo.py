
# ex : sudo python hw3_net.py -n 6

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import RemoteController, OVSSwitch
import sys, getopt


def MininetTopo(argv):

    net = Mininet()

    info("Create host nodes.\n")
    h1 = net.addHost('h1',ip="10.0.2.10/24",mac="00:00:00:00:00:01")
    h2 = net.addHost('h2',ip="10.0.2.11/24",mac="00:00:00:00:00:02")
    h3 = net.addHost('h3',ip="10.0.2.12/24",mac="00:00:00:00:00:03")
    h4 = net.addHost('h4',ip="10.0.1.10/24",mac="00:00:00:00:00:04")


    info("Create switch node.\n")
    s1 = net.addSwitch('s1',switch = OVSSwitch,failMode = 'secure',protocols = 'OpenFlow13')
    s2 = net.addSwitch('s2',switch = OVSSwitch,failMode = 'standalone',protocols = 'OpenFlow13')
    s3 = net.addSwitch('s3',switch = OVSSwitch,failMode = 'standalone',protocols = 'OpenFlow13')
    s4 = net.addSwitch('s4',switch = OVSSwitch,failMode = 'standalone',protocols = 'OpenFlow13')

    info("Create router node.\n")
    r1 = net.addHost('r1')
    r2 = net.addHost('r2')

    info("Create Links.\n")
    net.addLink(h4,s1)
    net.addLink(s1,r1)
    net.addLink(h1,s3)
    net.addLink(h2,s3)
    net.addLink(h3,s4)
    net.addLink(s3,s2)
    net.addLink(s4,s2)
    net.addLink(s2,r2)
    net.addLink(r1,r2)

    info("Create Controller.\n")
    c0 = net.addController(name = 'c0',controller = RemoteController,port = 6633)

    info("Build and start network.\n")
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([])
    s3.start([])
    s4.start([])

    r1.cmd("ifconfig r1-eth0 0")
    r1.cmd("ifconfig r1-eth1 0")
    r1.cmd("ifconfig r1-eth0 hw ether 00:00:00:00:01:01")
    r1.cmd("ifconfig r1-eth1 hw ether 00:00:00:00:01:02")
    r1.cmd("ip addr add 10.0.1.1/24 brd + dev r1-eth0")
    r1.cmd("ip addr add 10.0.3.1/24 brd + dev r1-eth1")
    r1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    r2.cmd("ifconfig r2-eth0 0")
    r2.cmd("ifconfig r2-eth1 0")
    r2.cmd("ifconfig r2-eth0 hw ether 00:00:00:00:02:01")
    r2.cmd("ifconfig r2-eth1 hw ether 00:00:00:00:02:02")
    r2.cmd("ip addr add 10.0.2.1/24 brd + dev r2-eth0")
    r2.cmd("ip addr add 10.0.3.2/24 brd + dev r2-eth1")
    r2.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    h1.cmd("ip route add default via 10.0.2.1")
    h2.cmd("ip route add default via 10.0.2.1")
    h3.cmd("ip route add default via 10.0.2.1")
    h4.cmd("ip route add default via 10.0.1.1")
    r1.cmd("ip route add default via 10.0.3.2")
    r2.cmd("ip route add default via 10.0.3.1")
    
    h4.cmd("python -m SimpleHTTPServer 80 &")

    info("Run mininet CLI.\n")
    CLI(net)

if __name__ == '__main__':
    setLogLevel('info')
    MininetTopo(sys.argv[1:])
