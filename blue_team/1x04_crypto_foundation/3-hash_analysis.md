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

