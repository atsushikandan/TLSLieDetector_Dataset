#!/bin/bash
CA_CONFIG="/ca/cnf/ca_cert.cnf"
CONFIG="/ca/cnf/openssl.cnf"

mkdir -p /ca/{certs,newcerts,private,output}
touch /ca/index.txt

openssl req -config $CA_CONFIG -new -x509 -noenc -newkey rsa:4096 -keyout /ca/private/cakey.pem -out /ca/output/cacert.pem

openssl req -config $CONFIG -new -noenc -newkey rsa:2048 -keyout /ca/output/rsa2048key.pem -out rsa2048cert.csr
openssl ca -config $CONFIG -create_serial -batch -in rsa2048cert.csr -out /ca/output/rsa2048cert.pem

openssl req -config $CONFIG -new -noenc -newkey EC:<(openssl ecparam -name secp521r1) -keyout /ca/output/ecsecp521r1key.pem -out ecsecp521r1cert.csr
openssl ca -config $CONFIG -create_serial -batch -in ecsecp521r1cert.csr -out /ca/output/ecsecp521r1cert.pem

openssl req -config $CONFIG -new -noenc -newkey ED25519 -keyout /ca/output/ed25519key.pem -out ed25519cert.csr
openssl ca -config $CONFIG -create_serial -batch -in ed25519cert.csr -out /ca/output/ed25519cert.pem
