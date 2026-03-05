from pathlib import Path
import argparse
import hashlib


def pk_ots_type(s: str):
    if not Path(s).exists():
        raise ValueError(f"Private key file {s} does not exist")
    if not Path(s).suffix == ".ots":
        raise ValueError(f"Private key file {s} is not a .ots file")
    return s


def sha3_256(data):
    return hashlib.sha3_256(data).digest()


parser = argparse.ArgumentParser(description="Sign a message using OTS")
parser.add_argument("message", type=str, help="The message to sign")
parser.add_argument(
    "private_key", type=pk_ots_type, help="private_key.ots key to sign hash with"
)

# produce (in invoked directory) file name signature.ots
# contains only the signature for `message` as per this simplified WOTS scheme
# (signing only the message digest digits, without any additional checksum)

w = 16  # Winternitz parameter
# -> signing is performed in groups of 4 successive bits
# each nibble’s numerical value is between 0 and 15

args = parser.parse_args()
msg = args.message
sk_ots = args.private_key
sk_bytes = Path(sk_ots).read_bytes()

with open(msg, "rb") as f:
    msg_hash = sha3_256(f.read())


d = []
for byte in msg_hash:
  # byte = <n0><n1>
  d.append(byte >> 4) # n1
  d.append(byte & 0x0f) # n0


signature_arr = []
assert len(d) == 64

for i in range(len(d)):
    # H^d[i] (sk)
    sk = sk_bytes[i*32 : (i+1)*32]
    for _ in range(d[i]):
        sk = sha3_256(sk)
    signature_arr.append(sk)

Path("signature.ots").write_bytes(b"".join(signature_arr))