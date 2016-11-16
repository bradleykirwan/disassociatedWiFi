#!/bin/bash

ADDR=192.168.1.75
DIR=disassociatedWiFi

sshpass -p 'raspberry' scp -r ~/disassociatedWiFi/* pi@$ADDR:~/$DIR/