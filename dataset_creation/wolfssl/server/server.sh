#!/bin/sh

tcpdump -i eth0 -nn -s 0 -U -w ${PCAP} tcp port 443 &
timeout 1 python /bin/server.py
sleep 0.5
kill %1