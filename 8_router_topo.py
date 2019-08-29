
# ex : sudo python hw3_net.py -n 6

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import RemoteController, OVSSwitch
import sys, getopt
import time
import threading

t = time.time()

def MininetTopo(argv):

    net = Mininet()

    info("Create host nodes.\n")
    
    host_ip = []

    hostlist = []
    hostlist.append(net.addHost('h1',ip="11.1.4.10/8",mac="00:00:00:00:00:10"))
    host_ip.append("11.1.4.10")
    count = 2
    for i in range(1,4):
        for j in range(1,4):
            hostname = "h"+str(count)
            host_ip.append("11."+str(i)+"."+str(j)+".10")
            ip_str = "11."+str(i)+"."+str(j)+".10/8"
            mac_str = "00:00:00:00:00:0"+str(count-1)
            hostlist.append (net.addHost(hostname,ip=ip_str,mac=mac_str))
            count+=1
    server = net.addHost('server',ip="10.0.1.10/8",mac="00:00:00:00:00:11")

    info("Create switch node.\n")
    s1 = net.addSwitch('s1',switch = OVSSwitch,failMode = 'standalone',protocols = 'OpenFlow13')
    s2 = net.addSwitch('s2',switch = OVSSwitch,failMode = 'standalone',protocols = 'OpenFlow13')
    s3 = net.addSwitch('s3',switch = OVSSwitch,failMode = 'standalone',protocols = 'OpenFlow13')
    s4 = net.addSwitch('s4',switch = OVSSwitch,failMode = 'standalone',protocols = 'OpenFlow13')
    s5 = net.addSwitch('s5',switch = OVSSwitch,failMode = 'standalone',protocols = 'OpenFlow13')

    info("Create router node.\n")
    r1 = net.addHost('r1')
    r2 = net.addHost('r2')

    info("Create Links.\n")
    net.addLink(server,s1)
    
    net.addLink(s1,r1)
    
    for i in range(0,4):
        net.addLink(hostlist[i],s3)
    for i in range(4,7):
        net.addLink(hostlist[i],s4)
    for i in range(7,10):
        net.addLink(hostlist[i],s5)
    
    net.addLink(s3,s2)
    net.addLink(s4,s2)
    net.addLink(s5,s2)

    net.addLink(s2,r2)
    net.addLink(r1,r2)
    
    info("Create Controller.\n")
    #c0 = net.addController(name = 'c0',controller = RemoteController,port = 6633)

    info("Build and start network.\n")
    net.build()
    net.start()

    r1.cmd("ifconfig r1-eth0 0")
    r1.cmd("ifconfig r1-eth1 0")
    r1.cmd("ifconfig r1-eth0 hw ether 00:00:00:00:01:01")
    r1.cmd("ifconfig r1-eth1 hw ether 00:00:00:00:01:02")
    r1.cmd("ip addr add 10.0.1.1/8 brd + dev r1-eth0")
    r1.cmd("ip addr add 12.0.3.1/8 brd + dev r1-eth1")
    r1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    r2.cmd("ifconfig r2-eth0 0")
    r2.cmd("ifconfig r2-eth1 0")
    r2.cmd("ifconfig r2-eth0 hw ether 00:00:00:00:02:01")
    r2.cmd("ifconfig r2-eth1 hw ether 00:00:00:00:02:02")
    r2.cmd("ip addr add 11.0.2.1/8 brd + dev r2-eth0")
    r2.cmd("ip addr add 12.0.3.2/8 brd + dev r2-eth1")
    r2.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    for i in range(0,10):
      hostlist[i].cmd("ip route add default via 11.0.2.1")

    server.cmd("ip route add default via 10.0.1.1")
    
    r1.cmd("ip route add default via 12.0.3.2")
    r2.cmd("ip route add default via 12.0.3.1")

    server.cmdPrint('cd ./file')
    server.cmdPrint("python -m SimpleHTTPServer 80 &")
    time.sleep(5)
    
    #s4.cmdPrint("xterm &")
    #hostlist[0].cmdPrint("xterm &")
    
    r1.cmdPrint("python sniffer.py r1 0 >"+argv[0]+"/r1.txt &")
    r2.cmdPrint("python sniffer.py r2 0 >"+argv[0]+"/r2.txt &")
    s1.cmdPrint("python sniffer.py s1 1 >"+argv[0]+"/s1.txt &")
    s2.cmdPrint("python sniffer.py s2 4 >"+argv[0]+"/s2.txt &")
    s3.cmdPrint("python sniffer.py s3 1 >"+argv[0]+"/s3.txt &")
    s4.cmdPrint("python sniffer.py s4 1 >"+argv[0]+"/s4.txt &")
    #s5.cmdPrint("python sniffer.py s5 1 2 3 >tran/s5.txt &")
 
    t = time.time()
    
    normal = threading.Thread(target = normal_testing,args = ([hostlist[4]]))
    
    normal.start()
    
    attack = threading.Thread(target = attack_testing,args = ([hostlist[0]]))
    
    attack.start()

    """
    info("Run mininet CLI.\n")
    CLI(net)
    """

def normal_testing(h):
    while True:
        if time.time()-t >= 240:
            print("stop!")
            return   

        h.cmdPrint('curl 10.0.1.10 &')
        time.sleep(20)

def attack_testing(h):
    while True:
        if time.time()-t >= 180:
            print("stop!")
            return
        h.cmd("hping3 10.0.1.10 -S -i u50000 -p 80")

if __name__ == '__main__':
    setLogLevel('info')
    MininetTopo(sys.argv[1:])

