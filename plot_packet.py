import matplotlib.pyplot as plt
import numpy as np

def plot():
    #x= [1,2,3]
    x = ['Firewall' , 'Openflow' , 'P4']
    p4 = 160/181*116
    y = [121,101,p4]
    plt.bar(x,height=y)
    plt.title ("Data traffic of switch(s1) after Syn Flooding")
    plt.ylabel ("Packet rate (thousand bytes/min)")

    plt.axhline(113,color = 'k',linestyle = '--')
    plt.text(1.5,117,"Benign data traffic",fontsize = 12,color = 'k')
    plt.savefig("packet_num.png",format="png")

if __name__ == '__main__':
    plot()
