#!bin/bash

set -eu

BASE_DIR=$(pwd)

function run () {
    cd $1
    bash $2
    cd ${BASE_DIR}
}

run base_image build.sh

run cert_generator build.sh
run cert_generator run.sh

run mbedtls build.sh

run openssl build.sh

run wolfssl build.sh

run faketls build.sh

run feature_collector build.sh
