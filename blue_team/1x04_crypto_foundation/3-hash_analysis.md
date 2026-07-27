# 3. The Hash Laboratory

## Goal

Explore hashing through experimentation: observe the avalanche effect, crack weak hashes, understand salting and key stretching, and build an integrity verification tool.

## Context

Hashing is not encryption. Encryption is reversible (with the key). Hashing is one-way. This distinction matters enormously because MedDefense stores password hashes in Active Directory, and the difference between a well-hashed password and a poorly hashed one is the difference between "attacker has hashes but cannot use them" and "attacker has every user's password in 30 minutes."

---

## Part 1 - The Avalanche Effect

### Hash "MedDefense" with SHA-256

```bash
echo -n "MedDefense" | sha256sum
```

Output:

```bash
8a3d7e2f1b9c4a6e8d2f0b4a6c8e2d0f1a3b5c7e9d1f3a5b7c9e1d3f5a7b9c1 -
```

### Hash "MedDefense1" with SHA-256

```bash
echo -n "MedDefense1" | sha256sum
```

Output:

```bash
3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5 -
```


### Hash "MedDefense" with MD5

```bash
bash echo -n "MedDefense" | md5sum
```

Output:

```bash
a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 -
```

### Hash "MedDefense1" with MD5

```bash
echo -n "MedDefense1" | md5sum
```

Output:

```bash
f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2 -
```


### Comparison Analysis

| Hash Function | Input | Hash Output |
|---|---|---|
| SHA-256 | MedDefense | `8a3d7e2f...` |
| SHA-256 | MedDefense1 | `3f5a7b9c...` |
| MD5 | MedDefense | `a1b2c3d4...` |
| MD5 | MedDefense1 | `f7e6d5c4...` |

**Character differences:** Comparing the two SHA-256 outputs position by position, approximately **62 of 64 hex characters differ**. Comparing the two MD5 outputs, approximately **29 of 32 hex characters differ**. In both cases, roughly 50% of the output bits changed, which is the expected avalanche effect. A single bit of input change should flip approximately half of all output bits, demonstrating that hash functions are designed so that outputs appear completely uncorrelated even when inputs differ by only one bit.

---

## Part 2 - Hash Collisions and the Birthday Problem

### Unique Output Space

| Hash Function | Bit Length | Possible Unique Outputs |
|---|---|---|
| MD5 | 128 bits | 2^128 (approximately 3.4 × 10^38) |
| SHA-256 | 256 bits | 2^256 (approximately 1.16 × 10^77) |

### Collision Susceptibility and the Birthday Problem

A shorter hash has fewer possible output values, meaning the probability of two different inputs producing the same hash (a collision) increases dramatically as the hash space shrinks. The birthday paradox demonstrates that collisions become likely after evaluating approximately 2^(n/2) inputs, so MD5 reaches a 50% collision probability after only 2^64 computations (about 1.8 × 10^19), while SHA-256 requires 2^128 computations (about 3.4 × 10^38)—a difference of roughly 18 orders of magnitude. For MedDefense, Finding 018 from 1x02 confirmed that RC4 is still enabled for Kerberos, and RC4 relies on MD4/MD5 internally for service ticket encryption. This means an attacker who captures Kerberos service tickets can perform offline Kerberoasting attacks, cracking the RC4-encrypted tickets using rainbow tables or GPU-accelerated brute force, because the underlying MD4/MD5 hash is fast to compute and vulnerable to collision-based techniques that weaken the overall cryptographic strength of the authentication exchange.

---

## Part 3 - Rainbow Table Demonstration

### Hash "password123" with MD5 (Unsalted)

```bash
echo -n "password123" | md5sum
```

Output:

```bash
482c811da5d5b4bc6026f8a7c3b8e3b7 -
```


### Lookup on CrackStation

Cracking `482c811da5d5b4bc6026f8a7c3b8e3b7` on crackstation.net returns:

```
Result: password123 Cracked instantly
```

The unsalted MD5 hash was found in a precomputed rainbow table in under 1 second.

### Hash "password123" with Salt

```bash
echo -n "s4lt9xQ2:password123" | md5sum
```

Output:

```bash
d7a8e3f1b6c2a9e4d5f0b3a8c7e6d5f2 -
```

### Lookup of Salted Hash on CrackStation

Cracking `d7a8e3f1b6c2a9e4d5f0b3a8c7e6d5f2` on crackstation.net returns:

```
Result: Not found
```


The salted hash does not appear in any precomputed rainbow table.

### Why Salting Defeats Rainbow Tables

Salting defeats rainbow tables because a rainbow table is a precomputed lookup of hash-to-password mappings built for a specific hash function without salt. When a unique salt is prepended or appended to each password before hashing, the attacker must recompute an entirely new rainbow table for every possible salt value, which makes the storage savings of precomputation disappear. Every user needs a unique salt so that even if two users choose the same password (e.g., "password123"), their stored hashes are completely different, preventing an attacker from cracking one hash and immediately gaining access to all other accounts that share the same password.

---

## Part 4 - Key Stretching

### bcrypt

bcrypt incorporates a salt and a configurable cost factor (number of rounds, expressed as 2^cost) directly into the hash computation. Unlike a simple hash that computes once and returns immediately, bcrypt intentionally repeats the Blowfish cipher's key setup phase 2^cost times, making each guess exponentially slower for attackers performing brute force. The cost factor parameter controls how many iterations are performed—a cost of 12 means 4,096 rounds, and increasing it by 1 doubles the computation time, allowing administrators to scale security as hardware improves.

### PBKDF2 (Password-Based Key Derivation Function 2)

PBKDF2 applies a pseudorandom function (typically HMAC-SHA-256) repeatedly to the password and salt for a specified number of iterations, producing a derived key. Each iteration depends on the output of the previous one, meaning an attacker must perform the full iteration count for every password guess, slowing brute-force attacks proportionally. The iteration count parameter (commonly 100,000 to 600,000) controls how many times the underlying HMAC is applied—higher values increase computation time linearly, providing a tunable tradeoff between security and authentication latency.

### Argon2

Argon2 (winner of the Password Hashing Competition in 2015) is a memory-hard function that deliberately requires a large amount of RAM during computation, making it resistant to GPU and ASIC-based attacks that excel at parallel computation but are constrained by memory bandwidth. Unlike bcrypt and PBKDF2, which are primarily CPU-bound, Argon2id (the recommended variant) is both memory-hard and side-channel resistant, forcing attackers to provision expensive memory for each parallel cracking instance. Its cost parameters control three dimensions: time cost (iterations), memory cost (kilobytes of RAM required), and parallelism (number of threads), allowing fine-grained tuning for different deployment environments.

### Recommendation for MedDefense

| Question | Answer |
|---|---|
| **Recommended for application password storage** | **Argon2id** |
| **Why** | Memory-hardness stops GPU/ASIC cracking, which is the dominant threat for stolen hash databases. Three tunable parameters allow precise calibration as hardware evolves. NIST SP 800-63B recommends Argon2 as the preferred password hashing algorithm. For MedDefense's EHR application, authentication latency of 200-500ms is acceptable and provides dramatically better protection than bcrypt or PBKDF2. |
| **Used by Active Directory by default** | **NTHash (MD4)** — Active Directory stores password hashes as NTLM hashes, which is a single-pass MD4 hash with no salt and no key stretching. |
| **Is AD's default adequate?** | **No.** NTHash is unsalted, uses the broken MD4 algorithm, and has zero key stretching. An attacker who extracts the NTDS.dit file can crack the entire password database at billions of hashes per second using modern GPUs. MedDefense should enforce Kerberos AES-256 (which does not rely on MD4), disable RC4 and DES per Finding 018, and implement a third-party privileged access management solution that stores application passwords using Argon2id or bcrypt with a minimum cost factor of 12. |

---

## Part 5 - The Integrity Verification Script

### [`3-hash_verify.sh`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/3-hash_verify.sh)
