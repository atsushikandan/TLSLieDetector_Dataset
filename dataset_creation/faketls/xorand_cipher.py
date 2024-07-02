#!/usr/bin/env python
import os
import pathlib
import random
import sys

LAZARUS_KEY1 = bytes.fromhex("47")
LAZARUS_KEY2 = bytes.fromhex("28")

PLAINTEXT_DIR=os.environ.get('PLAINTEXT_DIR')
OUTPUT_DIR=os.environ.get('OUTPUT_DIR')

REPEAT=int(sys.argv[1])

def enc(input:bytes, key1:bytes, key2:bytes) -> bytes:
    return b''.join([ (((b ^ int.from_bytes(key1)) + int.from_bytes(key2)) % 256 ).to_bytes() for b in input ])

def main():
    key_list = [ (random.randbytes(1),random.randbytes(1))  for r in range(REPEAT) ]
    key_list[0] = (LAZARUS_KEY1, LAZARUS_KEY2)

    for path in pathlib.Path(PLAINTEXT_DIR).glob("*.txt"):
        with path.open(mode='r') as f:
            content = f.read()

        for i,keys in enumerate(key_list):
            output_dir = pathlib.Path(OUTPUT_DIR).joinpath(f'xor-and_{i}_{keys[0].hex()}_{keys[1].hex()}')
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir.joinpath(f'FAKETLS-XOR-AND_{path.stem}_hex.txt')
            with output_path.open(mode='w') as f:
                f.write(enc(content.encode(), keys[0], keys[1]).hex())

if __name__ == "__main__":
    main()
