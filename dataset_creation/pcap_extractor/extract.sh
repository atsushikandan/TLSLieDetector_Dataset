#!/bin/bash

for pcap_path in $(find ${PCAP_DIR} -type f -name '*.pcap'); do
    pcap_basename=${pcap_path##*/}
    hextext_path="${HEXTEXT_DIR}/${pcap_basename%.*}_hex.txt"
    echo ${hextext_path}

    client_ip=$(tshark -r ${pcap_path} -Y "tls.handshake.type==1" -T fields -e ip.src | sort -u)
    if [[ -n "${client_ip}" ]]; then
        tshark -r ${pcap_path} -Y "ip.src==${client_ip} and tls.app_data" -T fields -e tls.app_data | sed "s/,//g" > ${hextext_path}
    fi
done
