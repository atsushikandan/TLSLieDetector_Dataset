#!/bin/sh

sleep 0.3
openssl s_client -connect server:443 -CAfile /cert/ca.pem -servername www.example.com $CLIENT_CIPHER_OPTION < ${PLAINTEXT}
