#!/usr/bin/env python3


from pathlib import Path
import subprocess
import secrets # secrets module, generates cryptographically strong random numbers
import hashlib

w = 16 # Winternitz parameter


def generateSecretKeyBlock() -> bytes:
    '''
    generates a cryptographically strong random bitstream of 256-bits
    as a block of the secret key
    '''
    return secrets.token_bytes(32)

def hashSecretKeyBlock(block: bytes) -> bytes:
    '''
    takes a 256-bit block (32-bytes) in hex, and applies SHA3-256 hash function 16 times
    returns the hashed block    
    '''
    return hashlib.sha3_256(block).digest()

def main():
    sk_arr = []
    pk_arr = []
    for _ in range(64):
        sk_i = generateSecretKeyBlock()
        cur = sk_i
        for _ in range(w):
            cur = hashSecretKeyBlock(cur)
        sk_arr.append(sk_i)
        pk_arr.append(cur)
    
    Path("private_key.ots").write_bytes(b"".join(sk_arr))
    Path("public_key.ots").write_bytes(b"".join(pk_arr))

if __name__ == "__main__":
    main()