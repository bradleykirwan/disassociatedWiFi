#!/bin/bash

ADDR=192.168.1.75
DIR=disassociatedWiFi

make
sshpass -p 'raspberry' scp main pi@$ADDR:~/$DIR/
sshpass -p 'raspberry' ssh pi@$ADDR "cd ~/$DIR/ && ./main"