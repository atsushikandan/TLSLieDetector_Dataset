#!/bin/sh

source ../run.env
PCAP_DIR="../${DATASET_DIR:-../dataset}/pcap/mbedtls/$(date +'%Y%m%d-%H%M%S')"
mkdir -p $PCAP_DIR

for plaintext in $(find ../${SOURCE_PLAINTEXT_DIR:-../dataset/source_plaintext} -type f -name "*.txt"); do
    for cipher in $(grep -v "^#" ./ciphers/ciphers.txt); do
        plaintext_basename=$(basename $plaintext)
        echo "PLAINTEXT=\"/plaintext/${plaintext_basename}\"" > tmp.env
        echo "CIPHER=\"${cipher}\"" >> tmp.env
        echo "PCAP=\"/pcap/mbedtls/${PCAP_DIR##*/}/${cipher}_${plaintext_basename%.*}.pcap\"" >> tmp.env
        docker compose --env-file ../run.env --env-file tmp.env up
        log_file="${PCAP_DIR}/${cipher}_${plaintext_basename%.*}.log"
        date > $log_file
        echo "=====" >> $log_file
        docker compose logs client >> $log_file
        echo "=====" >> $log_file
        docker compose logs server >> $log_file
        echo "=====" >> $log_file
        date >> $log_file
        docker compose down
    done
done
rm tmp.env
