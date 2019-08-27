from scapy.all import *
import sys
import threading

def pack_callback(packet):
    print(str(packet.time) + "\n" + str(len(packet)))

def sniffer(sw,eth):
    iface_name = sw+"-eth"+str(eth)
    #print("name " ,iface_name)
    sniff(iface = iface_name,prn=pack_callback)

if __name__ == '__main__':
    threads = []
    for i in sys.argv[2:]:
        threads.append(threading.Thread(target=sniffer,args=(sys.argv[1],i)))
    for t in threads:
        t.start()
