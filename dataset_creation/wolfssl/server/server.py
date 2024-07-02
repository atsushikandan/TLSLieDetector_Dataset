#!/usr/bin/env python
import os
import socket
import wolfssl


bind_socket = socket.create_server(("",443))
bind_socket.listen()

context = wolfssl.SSLContext(wolfssl.PROTOCOL_SSLv23, server_side=True)
context.load_cert_chain('/cert/cert.pem', '/cert/key.pem')
context.verify_mode = wolfssl.CERT_NONE

while True:
    try:
        secure_socket = None
        new_socket, from_addr = bind_socket.accept()
        secure_socket = context.wrap_socket(new_socket)

        print(f'Client: {from_addr}')

        data = ''
        recv = secure_socket.read()
        while(recv):
            data += recv.decode()
            recv = secure_socket.read()
        print('Received:\n', data, '\n')
    
    except:
        break

    finally:
        if secure_socket:
            secure_socket.close()

bind_socket.close()