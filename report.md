# CMPUT 333 – Assignment 2 Report
## Winternitz-Like One-Time Signature (Simplified WOTS)

---

## Build / Run Instructions

Starting from a clean Ubuntu 24.04 VM (via multipass):

```bash
# 1. Install Python 3.13+ and uv
sudo apt update && sudo apt install -y python3 python3-pip
pip install uv

# 2. Clone / copy the project directory, then enter it
cd cmput333assigment3

# 3. Set up the virtual environment
uv sync

# 4. Run the programs
uv run python ots_genkeys.py                          # generates private_key.ots and public_key.ots
uv run python ots_sign.py <message_file> private_key.ots    # produces signature.ots
uv run python ots_verify.py <message_file> public_key.ots signature.ots   # prints VALID or INVALID
```

No external dependencies beyond the Python standard library (`hashlib`, `secrets`, `pathlib`, `argparse`, `sys`) are required. SHA3-256 is provided by Python's built-in `hashlib` module (backed by OpenSSL).

---

## Code Overview

### `ots_genkeys.py`
Generates a fresh key pair each time it is invoked:
1. For each of the 64 chains (one per nibble of the 256-bit message digest):
   - Draws 32 cryptographically random bytes as the private seed using `secrets.token_bytes(32)`.
   - Computes the public value by iterating SHA3-256 sixteen times (w = 16) on the seed.
2. Writes all 64 private seeds concatenated (2 048 bytes) to `private_key.ots`.
3. Writes all 64 public values concatenated (2 048 bytes) to `public_key.ots`.

### `ots_sign.py`
Signs the contents of a file:
1. Reads the file and computes its SHA3-256 digest (32 bytes).
2. Splits the digest into 64 nibbles: for each byte, the high nibble goes to position `2i`, the low nibble to `2i+1`.
3. For chain `i`, hashes the private seed `d[i]` times (zero times if `d[i] == 0`, meaning the seed itself is the signature component).
4. Writes the 64 signature components concatenated (2 048 bytes) to `signature.ots`.

### `ots_verify.py`
Verifies a signature:
1. Reads the message file and computes its SHA3-256 digest, then extracts 64 nibbles identically to signing.
2. Reads `public_key.ots` and `signature.ots`.
3. For each chain `i`, hashes the signature component `16 - d[i]` times and checks against the public value.
4. Prints `VALID` if all 64 chains match; prints `INVALID` on the first mismatch.

---

## Question 1 – Validation

The following test cases were performed manually:

| Test | Expected | Actual |
|------|----------|--------|
| Generate keys → sign a test file → verify with matching key | VALID | VALID |
| Generate keys → sign `file_a` → verify with same public key but `file_b` | INVALID | INVALID |
| Generate keys → sign a file → tamper one byte in `signature.ots` → verify | INVALID | INVALID |
| Generate keys → sign a file → run `ots_genkeys` again (new key pair) → verify with new public key | INVALID | INVALID |
| Generate keys → sign a file → verify with `public_key.ots` and correct `signature.ots` but supply a different message file | INVALID | INVALID |
| Verify file sizes: all three `.ots` files must be exactly 2 048 bytes | — | Confirmed with `wc -c` |
| Run `ots_genkeys` three times and `diff` consecutive `private_key.ots` outputs | all differ | Confirmed |
| Sign the same file twice with two independently generated key pairs and cross-verify | INVALID | INVALID |

For the INVALID tests, tampering was introduced by flipping a single bit in the signature file using a short Python one-liner, confirming the verifier catches single-byte corruption.

---

## Question 2 – Uniqueness of Key Pairs

Each invocation of `ots_genkeys.py` produces an independent, unique key pair through two complementary mechanisms:

1. **Cryptographically secure random number generator (CSPRNG).**
   `secrets.token_bytes(32)` calls Python's `secrets` module, which on Linux reads from the kernel's `getrandom()` syscall (or `/dev/urandom`). This source is seeded from hardware entropy (interrupt timing, device noise, etc.) and is non-deterministic across invocations.

2. **256-bit seed space.**
   Each of the 64 private seeds is independently drawn from a space of 2^256 ≈ 1.16 × 10^77 possible values. The probability of any two invocations producing even a single matching seed is negligibly small (≈ 2^−256 per chain, and the full key pair collision probability is even smaller).

No persistent state or auxiliary files are used; uniqueness is guaranteed solely by the quality of the OS entropy pool, which continuously accumulates new entropy between invocations.

---

## Question 3 – Odds of Forging a Signature for Another Random File

**Background on the vulnerability.**
In this simplified WOTS (without checksum), for chain `i`:
- The signature component is `sig[i] = H^(d[i])(sk[i])`.
- Verification hashes `sig[i]` another `16 − d[i]` times and checks against `pk[i] = H^16(sk[i])`.

If we hold the valid signature for the Module 1 slides (with known nibble values `d[0], …, d[63]`), we can forge a valid signature for a **different** file whose hash nibbles are `d'[0], …, d'[63]` if and only if `d'[i] ≥ d[i]` for **every** `i`. This is because hashing forward (applying SHA3-256 more times) is always feasible, but inverting the hash is not.

**Probability calculation.**
For a uniformly random target file, each nibble `d'[i]` is independently and uniformly distributed over `{0, 1, …, 15}`. The probability that a single nibble satisfies `d'[i] ≥ d[i]` is:

```
P(d'[i] ≥ d[i]) = (16 − d[i]) / 16
```

Since we do not have the Module 1 slides to compute the exact values `d[i]`, we use the expected per-chain probability averaged over a uniformly random original message:

```
E[P(d'[i] ≥ d[i])] = (1/16) · Σ_{k=0}^{15} (16−k)/16
                    = (1/16) · (16+15+…+1)/16
                    = (1/16) · 136/16
                    = 136/256
                    = 17/32 ≈ 0.531
```

Because all 64 nibbles must satisfy the condition simultaneously, and they are independent:

```
P(forgery succeeds) ≈ (17/32)^64
                    = 2^(64 · log₂(17/32))
                    ≈ 2^(64 · (−0.913))
                    ≈ 2^(−58.4)
                    ≈ 3 × 10^(−18)
```

**Conclusion.** The odds are roughly **1 in 2^58** (about 1 in 3 × 10^17). While this is vastly better than brute-forcing a 256-bit hash (1 in 2^256), it is still far below any practical threshold for a real-world attack. The exact probability depends on the specific nibble values of the Module 1 slides' hash, but the expected order of magnitude is ≈ 2^−58.

---

## Question 4 – Why the Summation Checksum Is Not a Concern in WOTS

**The standard concern with summation checksums.**
In traditional data integrity schemes (e.g., simple CRC or Luhn), a summation checksum is weak because an adversary can freely increase one field value and decrease another by the same amount, preserving the sum while modifying the data undetected.

**Why this attack fails in WOTS.**
In WOTS, the hash chains enforce a strict one-way ordering on nibble values:

- **Increasing** a nibble `d[i]` to `d'[i] > d[i]` is feasible: the attacker hashes `sig[i]` an additional `d'[i] − d[i]` times. This is a forward operation.
- **Decreasing** a nibble `d[i]` to `d'[i] < d[i]` is infeasible: it would require computing `H^(−Δ)(sig[i])`, i.e., inverting SHA3-256 — a cryptographically hard preimage problem.

For the "rearrange while keeping sum constant" attack to succeed, the adversary would need to *increase* some nibbles and *decrease* others. Since decreasing any nibble is computationally infeasible, the entire attack is blocked.

**The complementary checksum reinforces this.**
WOTS in practice uses a complementary checksum `C = Σ(w−1−d[i])`. When an adversary increases message nibbles (which is the only feasible direction), the checksum `C` *decreases*. Forging the checksum signature for smaller checksum-nibble values would require backward hash-chain operations — again infeasible. This interlocking of message and checksum chains means that any attempt to bias the message nibbles upward is automatically caught by the checksum chains being forced downward, where the attacker has no valid preimages.

In short, the one-way property of the underlying hash function transforms the ordinarily weak summation checksum into a cryptographically secure binding, because the adversary lacks the freedom to freely decrease values that traditional checksum attacks require.
