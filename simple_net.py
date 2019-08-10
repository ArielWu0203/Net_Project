
# ex : sudo python hw3_net.py -n 6

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import RemoteController, OVSSwitch
import sys, getopt


def MininetTopo(argv):

    number = 0

    try:
        opts,args = getopt.getopt(argv,"n:",["number="])
    except getopt.GetoptError:
        print("hw3_net.py -n <number>")
        sys.exit(2)
    for opt,arg in opts:
        if opt in ("-n","--number"):
            number = int(arg)
    print ("number=%d" %number)
    
    net = Mininet()

    info("Create host nodes.\n")
    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    h2.cmd("python -m SimpleHTTPServer 80 &")
    h3 = net.addHost('h3')

    info("Create switch node.\n")
    switch = []
    for i in range(1,number+1):
        switch_name = "s" + str(i)
        switch.append(net.addSwitch(switch_name,switch = OVSSwitch,failMode = 'secure',protocols = 'OpenFlow13'))

    info("Create Links.\n")
    net.addLink(h1,switch[0])
    net.addLink(h3,switch[0])

    net.addLink(h2,switch[number-1])
    for i in range(number-1):
        net.addLink(switch[i],switch[i+1])

    info("Create Controller.\n")
    net.addController(name = 'c0',controller = RemoteController,ip = '127.0.0.1',port = 6633)

    info("Build and start network.\n")
    net.build()
    net.start()

    info("Run mininet CLI.\n")
    CLI(net)

if __name__ == '__main__':
    setLogLevel('info')
    MininetTopo(sys.argv[1:])
