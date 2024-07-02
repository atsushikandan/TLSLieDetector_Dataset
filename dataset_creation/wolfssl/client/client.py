#!/usr/bin/env python
import os
import socket
import wolfssl


file_to_send = os.environ.get('PLAINTEXT')
cipher = os.environ.get('CIPHER')

version = wolfssl.PROTOCOL_TLSv1_3 if cipher.startswith('TLS13-') else wolfssl.PROTOCOL_TLSv1_2

context = wolfssl.SSLContext(version)
context.verify_mode = wolfssl.CERT_NONE
context.set_ciphers(cipher)

if cipher.startswith('TLS13-'):
    print('TLS Version: TLS 1.3')
else:
    print('TLS Version: TLS 1.2')

print(f'Cipher Suites: {cipher}')

secure_socket = context.wrap_socket(socket.socket())    
secure_socket.connect(('server', 443))

with open(file_to_send) as f:
    content = f.read()
    print(f'Send: \n{content}')
    secure_socket.write(content)

secure_socket.close()