# Net_Project
## simple_net.py
* h1 -- switches -- h2
* Example:  
  h1 -- s1 -- s2 -- s3 -- h2
  ```
  $ sudo python simple_net.py -n 3
  ```
## TCP_RyuApp.py
  ```
  $ ryu-manager TCP_RyuApp.py
  ```
  * 當有syn pakets 時會輸出:
  {switch number : {dstination ip : {in_port : [] , source ip : packet count}}}
## ps
* 做完要清空 : 
  ```
  $ sudo mn -c
  ```
## simple_router.py
* h1--s1--r1--s2--h1
## Router_topo.py
![image](https://github.com/ArielWu0203/Net_Project/blob/master/net.png?raw=true)
