#!/usr/bin/env python
import os
import pathlib
import random
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7

PLAINTEXT_DIR=os.environ.get('PLAINTEXT_DIR')
OUTPUT_DIR=os.environ.get('OUTPUT_DIR')
KEY_BYTES=os.environ.get('KEY_BYTES')

REPEAT=int(sys.argv[1])

def add_padding(data, block_size=128):
    padder = PKCS7(block_size).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data

def aes_cbc_encrypt(key, iv, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return encrypted_data

def main():
    key_list = [ random.randbytes(int(KEY_BYTES)) for r in range(REPEAT) ]
    iv_list = [ random.randbytes(16) for r in range(REPEAT) ]

    for path in pathlib.Path(PLAINTEXT_DIR).glob("*.txt"):
        with path.open(mode='r') as f:
            content = f.read()

        for i,(key, iv) in enumerate(zip(key_list, iv_list)):
            output_dir = pathlib.Path(OUTPUT_DIR).joinpath(f'aes{int(KEY_BYTES) * 8}-cbc_{i}_{key.hex()}_{iv.hex()}')
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir.joinpath(f'FAKETLS-AES{int(KEY_BYTES) * 8}-CBC_{path.stem}_hex.txt')
            with output_path.open(mode='w') as f:
                padded_content = add_padding(content.encode())
                encrypted_data = aes_cbc_encrypt(key, iv, padded_content)
                f.write(encrypted_data.hex())

if __name__ == "__main__":
    main()
