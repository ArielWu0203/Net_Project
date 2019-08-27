import matplotlib.pyplot as plt                                                     
import numpy as np

def plot_controller(file1,file2):
    
    fp1 = open(file1,"r")
    fp2 = open(file2,"r")
    
    time = []
    time2 = []
    
    data1 = []
    data2 = []
    
    lines = fp1.readlines()
    fp1.close()

    for i in range(0,len(lines),2):

        lines[i] = lines[i].strip('\n')
        lines[i] = float(lines[i])
        time.append(lines[i])   
        
        lines[i+1] = int(lines[i+1])
        data1.append(lines[i+1])    
        
    lines = []
    lines = fp2.readlines()
    fp2.close()

    for i in range(0,len(lines),2):

        lines[i] = lines[i].strip('\n')
        lines[i] = float(lines[i])
        time2.append(lines[i])   
        
        lines[i+1] = int(lines[i+1])
        data2.append(lines[i+1])    
    
    
    line1 = plt.plot(time,data1,'-',label = 'Openflow')
    plt.title("Data traffic of Controller")
    plt.xlabel("time(sec)")
    plt.ylabel("Packet rate(bytes/sec)")

    plt.axvline(60,0,5000,linestyle='--',color = 'k')
    
    line2 = plt.plot(time2,data2,'-',label = 'P4')
    
    plt.legend(loc = 'upper right')

    plt.text(62,8700,"Syn flooding",fontsize = 12,color = 'k')
    #plt.show()

    plt.savefig("data_traffic.png",format="png")

if __name__ == '__main__':

    plot_controller("test.txt","p4.txt")
