import matplotlib.pyplot as plt
import numpy as np

def plot():

    no_x = [0,5,10,20,25,40]
    no_y = [22113/1000,260230/1000,499428/1000,994566/1000,1176930/1000,1923062/1000]
    no_line = plt.plot(no_x,no_y,'-',marker = 'o',mfc = 'w',label = "No defense")
 
    
    tran_x = [0,5,10,20,25,40]
    tran_y = [21815/1000,85790/1000,141238/1000,271262/1000,341586/1000,530549/1000]
    tran_line = plt.plot(tran_x,tran_y,'-',marker = 'p',mfc = 'w',label = "Firewall")
    
    of_x = [0,5,10,20,25,40]
    of_y = [20468/1000,39838/1000,59588/1000,89130/1000,103932/1000,151748/1000]
    of_line = plt.plot(of_x,of_y,'-',marker = 's',lw = 1.5,mfc= 'w',label = "Openflow")
    
    p4_x = [0,5,10,20,25,40]
    p4_y = [19049/1000,35547/1000,51432/1000,81689/1000,98226/1000,145075/1000]
    p4_line = plt.plot(p4_x,p4_y,'--',marker = '^',mfc = 'w',label = "P4")

    plt.title ("Effect of Syn Flood Attack on network traffic")
    plt.ylabel ("Total throughput (thousand bytes/min)")
    plt.xlabel ("attack rate (times/sec)")
    plt.legend(loc = 'upper left')
    
    #plt.show()
    plt.savefig("packet_num.png",format="png")

if __name__ == '__main__':
    plot()
