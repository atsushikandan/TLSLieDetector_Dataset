#!/bin/sh

tcpdump -i eth0 -nn -s 0 -U -w ${PCAP} tcp port 443 &
timeout 1 openssl s_server -cert /cert/cert.pem -key /cert/key.pem -accept 443 -cipher "ALL"
sleep 0.5
kill %1