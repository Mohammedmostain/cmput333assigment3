import sys
import hashlib

def sha3_256(data):
    return hashlib.sha3_256(data).digest()

def ots_verify(msg_file, pub_key_file, sig_file):
    # 1. Hash the message and extract nibbles (same as signing)
    with open(msg_file, "rb") as f:
        msg_hash = sha3_256(f.read())
    
    nibbles = []
    for byte in msg_hash:
        nibbles.append(byte >> 4)
        nibbles.append(byte & 0x0F)

    # 2. Load Public Key and Signature [cite: 86]
    with open(pub_key_file, "rb") as f:
        pub_data = f.read()
    with open(sig_file, "rb") as f:
        sig_data = f.read()

    # 3. Verify each of the 64 chains
    for i in range(64):
        sig_component = sig_data[i*32 : (i+1)*32]
        pub_component = pub_data[i*32 : (i+1)*32]
        
        # Hash signature component (16 - d[i]) times
        curr = sig_component
        for _ in range(16 - nibbles[i]):
            curr = sha3_256(curr)
        
        # 4. Check if it matches the Public Key
        if curr != pub_component:
            print("INVALID")
            return

    print("VALID")

if __name__ == "__main__":
    if len(sys.argv) == 4:
        ots_verify(sys.argv[1], sys.argv[2], sys.argv[3])