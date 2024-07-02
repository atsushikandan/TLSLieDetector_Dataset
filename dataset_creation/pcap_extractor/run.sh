#!/bin/bash

source ../run.env

for pcap_path in $(find ../${DATASET_DIR:-../dataset}/pcap -type f -name '*.pcap'); do
    pcap_dirname=${pcap_path%/*}
    pcap_basename=${pcap_path##*/}
    hextext_path="${pcap_dirname/pcap/hextext}/${pcap_basename%.*}_hex.txt"
    echo ${hextext_path}
    mkdir -p ${hextext_path%/*}

    echo "PCAP_DIR=\"/pcap/${pcap_dirname##*/pcap/}\"" > tmp.env
    echo "HEXTEXT_DIR=\"/hextext/${pcap_dirname##*/pcap/}\"" >> tmp.env
    docker compose --env-file ../run.env --env-file tmp.env up tshark
    docker compose down
done
rm tmp.env
