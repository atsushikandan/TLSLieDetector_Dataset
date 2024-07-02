#!/bin/sh

ssl_client2_custom \
    server_name=www.example.com \
    server_addr=server \
    server_port=443 \
    ca_file=/cert/ca.pem \
    max_version=tls13 \
    force_ciphersuite=${CIPHER} \
    file_to_send=${PLAINTEXT}
