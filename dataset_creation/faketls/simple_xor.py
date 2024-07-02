#!/usr/bin/env python
import os
import pathlib
import random
import sys
from itertools import cycle

PLAINTEXT_DIR=os.environ.get('PLAINTEXT_DIR')
OUTPUT_DIR=os.environ.get('OUTPUT_DIR')

REPEAT=int(sys.argv[1])


def xor(input:bytes, key:bytes) -> bytes:
    return bytes(input_byte ^ key_byte for (input_byte,key_byte) in zip(input, cycle(key)))

def main():
    key_list = [ random.randbytes(1)  for r in range(REPEAT) ]

    for path in pathlib.Path(PLAINTEXT_DIR).glob("*.txt"):
        with path.open(mode='r') as f:
            content = f.read()

        for i,key in enumerate(key_list):
            output_dir = pathlib.Path(OUTPUT_DIR).joinpath(f'xor_{i}_{key.hex()}')
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir.joinpath(f'FAKETLS-XOR_{path.stem}_hex.txt')
            with output_path.open(mode='w') as f:
                f.write(xor(content.encode(), key).hex())

if __name__ == "__main__":
    main()
