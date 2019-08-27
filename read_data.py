from scapy.all import *

def read_data(file_name):
    pcaps = rdpcap(file_name)
    first_time = float(pcaps[0].time)
    time_step = []
    total = []

    temp  = file_name.split('.')
    output_file = temp[0]+".txt"
    f = open(output_file,'wb')

    for i in range(0,len(pcaps)) :
        packet = pcaps[i]
        time = float(packet.time)
        size = len(packet)
        
        time_step.append(time-first_time)
        total.append(size)
        
        if time-first_time > 125:
            break
        
    #print(time_step)
    #print(total)
    
    num = 0
    prev_a = 0

    for i in range(0,len(time_step)):
        if (i+1) < len(time_step) and round(time_step[i],0) == round(time_step[i+1],0):
            num+=total[i]
        else :
            num += total[i]
            a = round(time_step[i])
            
            for j in range(prev_a+1,int(a)):
                f.write(str(j)+ "\n" + str(0) + "\n")
            f.write(str(a) + "\n" + str(num) + "\n")
            num = 0
            prev_a = int(a)

            #print("prev_a",prev_a)

    f.close()
if __name__ == '__main__':
    read_data("p4.pcap")

