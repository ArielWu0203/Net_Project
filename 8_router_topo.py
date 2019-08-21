
# ex : sudo python hw3_net.py -n 6

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import RemoteController, OVSSwitch
import sys, getopt
import time

def MininetTopo(argv):

    net = Mininet()

    info("Create host nodes.\n")
    

    count = 1
    hostlist = []
    for i in range(1,4):
        for j in range(1,4):
            hostname = "h"+str(count)
            ip_str = "11."+str(i)+"."+str(j)+".10/8"
            mac_str = "00:00:00:00:00:0"+str(count)
            hostlist.append (net.addHost(hostname,ip=ip_str,mac=mac_str))
            count+=1
    server = net.addHost('server',ip="10.0.1.10/8",mac="00:00:00:00:00:15")
    attacker = net.addHost('attacker',ip="11.1.1.11/8",mac="00:00:00:00:00:16")
    
    for i in range(1,4):
        hostname = "h"+str(count)
        ip_str = "13.1."+str(i)+".10/8"
        mac_str = "00:00:00:00:00:"+str(count)
        hostlist.append (net.addHost(hostname,ip=ip_str,mac=mac_str))
        count+=1
    for i in range(1,3):
        hostname = "h"+str(count)
        ip_str = "13.2."+str(i)+".10/8"
        mac_str = "00:00:00:00:00:"+str(count)
        hostlist.append (net.addHost(hostname,ip=ip_str,mac=mac_str))
        count+=1



    info("Create switch node.\n")
    s1 = net.addSwitch('s1',switch = OVSSwitch,failMode = 'standalone',protocols = 'OpenFlow13')
    s2 = net.addSwitch('s2',switch = OVSSwitch,failMode = 'standalone',protocols = 'OpenFlow13')
    s5 = net.addSwitch('s5',switch = OVSSwitch,failMode = 'standalone',protocols = 'OpenFlow13')


    info("Create router node.\n")
    r1 = net.addHost('r1')
    r2 = net.addHost('r2')

    info("Create Links.\n")
    net.addLink(server,s1)
    net.addLink(s1,r1)
    for i in range(0,9):
        net.addLink(hostlist[i],s2)

    net.addLink(attacker,s2)

    net.addLink(s2,r2)
    net.addLink(r1,r2)
    net.addLink(s5,r2)
    for i in range(9,14):
        net.addLink(hostlist[i],s5)
    
    info("Create Controller.\n")
    c0 = net.addController(name = 'c0',controller = RemoteController,port = 6633)

    info("Build and start network.\n")
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([])
    s5.start([])

    r1.cmd("ifconfig r1-eth0 0")
    r1.cmd("ifconfig r1-eth1 0")
    r1.cmd("ifconfig r1-eth0 hw ether 00:00:00:00:01:01")
    r1.cmd("ifconfig r1-eth1 hw ether 00:00:00:00:01:02")
    r1.cmd("ip addr add 10.0.1.1/8 brd + dev r1-eth0")
    r1.cmd("ip addr add 12.0.3.1/8 brd + dev r1-eth1")
    r1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    r2.cmd("ifconfig r2-eth0 0")
    r2.cmd("ifconfig r2-eth1 0")
    r2.cmd("ifconfig r2-eth2 0")
    r2.cmd("ifconfig r2-eth0 hw ether 00:00:00:00:02:01")
    r2.cmd("ifconfig r2-eth1 hw ether 00:00:00:00:02:02")
    r2.cmd("ifconfig r2-eth2 hw ether 00:00:00:00:02:03")
    r2.cmd("ip addr add 11.0.2.1/8 brd + dev r2-eth0")
    r2.cmd("ip addr add 12.0.3.2/8 brd + dev r2-eth1")
    r2.cmd("ip addr add 13.0.2.1/8 brd + dev r2-eth2")
    r2.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    for i in range(0,9):
      hostlist[i].cmd("ip route add default via 11.0.2.1")
    
    attacker.cmd("ip route add default via 11.0.2.1")

    server.cmd("ip route add default via 10.0.1.1")
    
    for i in range(9,14):
      hostlist[i].cmd("ip route add default via 13.0.2.1")
    
    r1.cmd("ip route add default via 12.0.3.2")
    r2.cmd("ip route add default via 12.0.3.1")

    server.cmdPrint("python -m SimpleHTTPServer 80 &")
    time.sleep(3)
    
    attacker.cmdPrint('xterm &')
    #s1.cmdPrint('xterm &')


    while True:
        for i in range(0,3):
            hostlist[i].cmdPrint('curl 10.0.1.10 &')

        time.sleep(10)
    
    info("Run mininet CLI.\n")
    CLI(net)

if __name__ == '__main__':
    setLogLevel('info')
    MininetTopo(sys.argv[1:])

