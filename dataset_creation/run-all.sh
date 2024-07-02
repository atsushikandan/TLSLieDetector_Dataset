#!bin/bash

set -eu

BASE_DIR=$(pwd)

function run () {
    cd $1
    bash $2
    cd ${BASE_DIR}
}

run mbedtls run.sh

run openssl run.sh

run wolfssl run.sh

run pcap_extractor run.sh

run faketls run.sh

run feature_extractor run.sh
