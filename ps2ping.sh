#!/bin/bash

PS2IP="192.168.100.11"
ETH="eth0"
ETHIP="192.168.100.2"
ETHMASK="255.255.255.0"

while true
do
	ping -c 1 -W 1 $PS2IP
    if [ ! "$?" == "0" ]; then
        ifconfig $ETH inet $ETHIP netmask $ETHMASK up
    fi
	sleep 1
done

