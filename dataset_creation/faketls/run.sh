#!/bin/bash

source ../run.env

mkdir -p "${DATASET_DIR}/hextext/faketls/XOR"
mkdir -p "${DATASET_DIR}/hextext/faketls/XOR_AND"
mkdir -p "${DATASET_DIR}/hextext/faketls/RC4"
mkdir -p "${DATASET_DIR}/hextext/faketls/AES_256_CBC"

docker compose --env-file ../run.env up
