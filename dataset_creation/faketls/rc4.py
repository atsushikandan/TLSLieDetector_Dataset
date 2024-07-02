#!/usr/bin/env python
import os
import pathlib
import random
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

LAZARUS_KEY=bytes.fromhex("79E10A5D877D9FF75D122E1165ACE325")

PLAINTEXT_DIR=os.environ.get('PLAINTEXT_DIR')
OUTPUT_DIR=os.environ.get('OUTPUT_DIR')

REPEAT=int(sys.argv[1])

def rc4_encrypt(key, data):
    cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data)
    return encrypted_data

def main():
    key_list = [ random.randbytes(16) for r in range(REPEAT) ]
    key_list[0] = LAZARUS_KEY

    for path in pathlib.Path(PLAINTEXT_DIR).glob("*.txt"):
        with path.open(mode='r') as f:
            content = f.read()

        for i,key in enumerate(key_list):
            output_dir = pathlib.Path(OUTPUT_DIR).joinpath(f'rc4_{i}_{key.hex()}')
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir.joinpath(f'FAKETLS-RC4_{path.stem}_hex.txt')
            with output_path.open(mode='w') as f:
                encrypted_data = rc4_encrypt(key, content.encode())
                f.write(encrypted_data.hex())

if __name__ == "__main__":
    main()
