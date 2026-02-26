#!/usr/bin/env python3


from pathlib import Path
import subprocess
import secrets # secrets module, generates cryptographically strong random numbers

def generateSecretKeyBlock() -> bytes:
    '''
    generates a cryptographically strong random bitstream of 256-bits
    as a block of the secret key
    '''
    return secrets.token_hex(32)

def hashSecretKeyBlock(hexBlock:bytes) -> bytes:
    '''
    takes a 256-bit block (32-bytes) in hex, and applies SHA3-256 hash function 64 times
    returns the hashed block    
    '''
    result = subprocess.run(
        [
            "openssl", "dgst", "-sha3-256"
        ],
        input=hexBlock.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return extractHashedBlock(result.stdout)

def extractHashedBlock(output:bytes):
    outputStr = output.decode()
    hashedBlock = outputStr.split("=")[1].strip()
    return hashedBlock

def main():
    block = generateSecretKeyBlock()
    print(block)
    print(hashSecretKeyBlock(block))

if __name__ == "__main__":
    main()