#!/bin/bash
echo "tranditional"
python read_packet.py tran/s1.txt tran/s2.txt tran/s3.txt tran/s4.txt tran/r1.txt tran/r2.txt
echo "Openflow"
python read_packet.py OF/s1.txt OF/s2.txt OF/s3.txt OF/s4.txt OF/r1.txt OF/r2.txt
