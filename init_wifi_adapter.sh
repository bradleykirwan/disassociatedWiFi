#!/bin/bash

if [ $# -eq 0 ]
	then
		me=`basename "$0"`
		echo "Usage: ./$me <phy-interface> [channel]"
		exit 1
fi

CHANNEL=${2:-13}

ifconfig $1 down
iw dev $1 set monitor otherbss fcsfail
ifconfig $1 up
iwconfig $1 channel $CHANNEL
ifconfig $1 mtu 2000 # Allows us to have MTU of at least 1500 for virtual interface
