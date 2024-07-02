#!/bin/sh

tcpdump -i eth0 -nn -s 0 -U -w ${PCAP} tcp port 443 &
timeout 1 ssl_server2_custom \
    crt_file=/cert/cert.pem \
    key_file=/cert/key.pem \
    server_port=443 \
    max_version=tls13
sleep 0.5
kill %1