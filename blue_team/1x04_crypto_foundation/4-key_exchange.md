# 4. The Key Exchange

## Goal

Simulate a Diffie-Hellman key exchange with OpenSSL to understand how two parties agree on a shared secret over an insecure channel, then analyze the man-in-the-middle vulnerability that certificates exist to solve.

## Context

The fundamental problem of symmetric encryption is key distribution: Alice and Bob need the same key, but they cannot send it over the network because Eve is listening. In 1976, Whitfield Diffie and Martin Hellman solved this problem with mathematics. You are about to reproduce their solution with OpenSSL. But their solution has a weakness. If Eve is not just listening but actively intercepting and modifying traffic, Diffie-Hellman alone cannot detect her. This is why certificates exist. The connection between key exchange and PKI is the thread that runs through the rest of this project.

---

## Part 1 - The DH Simulation

### Step 1: Generate Shared DH Parameters

Alice and Bob first agree on public DH parameters (a large prime number and a generator). These are not secret and can be sent over the insecure channel.

```bash
openssl dhparam -out dhparams.pem 2048
```

This generates a 2048-bit safe prime and saves it as `dhparams.pem`. Both parties need these same parameters.

### View the parameters

```bash
openssl dhparam -in dhparams.pem -text -noout
```

Output:

```bash
    DH Parameters: (2048 bit)
    P:   
        00:e9:33:8c:d0:82:a0:83:46:29:f9:90:3a:ad:a2:
        55:c6:85:f1:a8:07:70:9a:56:d7:15:43:b2:c2:e0:
        08:86:5e:7c:95:ac:fb:2a:51:c5:22:53:f3:a9:15:
        fa:ff:cb:47:bc:79:13:c0:07:48:19:d4:ce:cb:5c:
        e5:3c:64:fa:16:08:88:49:fb:d6:24:fc:2e:fd:36:
        3f:11:df:d4:25:ce:a3:f0:1c:c4:f1:d6:c0:91:3b:
        30:64:c7:51:52:66:e8:43:1e:ed:8a:6f:df:5c:c1:
        46:6d:0c:21:f4:e7:48:6b:86:aa:dc:80:5d:f4:bc:
        eb:50:b1:42:55:1a:fc:c4:5d:20:68:78:97:12:b5:
        12:65:de:f5:9b:10:fa:3e:30:2e:f2:30:f2:bd:73:
        77:5c:43:11:c1:07:0a:d0:49:c0:01:d4:0a:ae:ad:
        10:e0:99:84:93:79:23:50:e9:78:a2:c5:35:83:67:
        0f:d7:66:0e:31:71:f3:f9:0e:64:18:a5:b8:f6:2a:
        be:31:3c:8c:a6:99:fa:7d:8a:b4:84:c5:0a:85:3b:
        e7:b9:2d:a9:44:77:54:1e:d2:96:d5:2c:aa:d8:97:
        17:78:5a:13:51:60:22:04:19:78:59:9b:0c:02:d3:
        b3:f9:94:17:33:17:38:90:28:7c:72:98:a9:dc:e8:
        db:f7
    G:    2 (0x2)
    recommended-private-length: 225 bits
```

### Step 2: Generate Alice's Private Key

```bash
openssl genpkey -paramfile dhparams.pem -out alice_dh_priv.pem
```

### Step 3: Extract Alice's Public Key

```bash
openssl pkey -in alice_dh_priv.pem -pubout -out alice_dh_pub.pem
```

Verify:

```bash
openssl pkey -in alice_dh_pub.pem -pubin -text -noout
```

Output:

```bash
DH Public-Key: (2048 bit)
public-key:
    00:a4:1f:66:a7:a0:f8:c4:ab:fe:57:5b:c9:87:6a:
    44:a9:21:94:9e:0f:bf:2a:6e:be:30:10:ba:a5:39:
    f4:93:af:df:c3:ff:5e:e4:d1:b7:1d:b7:d4:92:32:
    99:51:2b:bd:6a:07:85:3c:bd:5c:98:fb:b4:31:51:
    e1:63:42:38:e5:53:10:ba:19:49:f4:83:8f:66:95:
    d2:2c:ae:8d:63:0f:26:91:da:71:5e:ab:ac:93:7d:
    5f:a0:33:88:b2:2a:26:ce:d1:df:a5:4c:30:c7:72:
    3a:0b:40:3e:36:a1:9f:cf:48:68:60:2b:c0:79:0a:
    93:e0:5e:ef:1b:22:ca:82:48:19:19:cd:12:e8:ee:
    6a:f6:62:b1:bf:5e:45:6c:3a:ac:e9:2f:70:d3:f9:
    75:62:3b:6c:88:20:8f:d6:56:be:fd:ab:f8:96:af:
    06:2c:7d:00:53:1a:03:83:73:65:8f:23:58:2b:c0:
    6b:4f:e8:98:80:f5:2c:72:ad:d5:77:a4:c3:a5:ff:
    fd:e0:49:f8:a2:3d:5f:08:2c:38:0b:fd:68:51:55:
    d2:3c:1f:c8:88:de:40:1f:2e:14:fb:d7:86:c9:24:
    e3:a3:f2:96:b0:fd:4a:6d:84:9d:eb:f6:82:27:d4:
    54:bf:c6:c4:c9:7b:78:5b:48:15:3a:8e:fa:0f:35:
    41:2e
P:   
    00:e9:33:8c:d0:82:a0:83:46:29:f9:90:3a:ad:a2:
    55:c6:85:f1:a8:07:70:9a:56:d7:15:43:b2:c2:e0:
    08:86:5e:7c:95:ac:fb:2a:51:c5:22:53:f3:a9:15:
    fa:ff:cb:47:bc:79:13:c0:07:48:19:d4:ce:cb:5c:
    e5:3c:64:fa:16:08:88:49:fb:d6:24:fc:2e:fd:36:
    3f:11:df:d4:25:ce:a3:f0:1c:c4:f1:d6:c0:91:3b:
    30:64:c7:51:52:66:e8:43:1e:ed:8a:6f:df:5c:c1:
    46:6d:0c:21:f4:e7:48:6b:86:aa:dc:80:5d:f4:bc:
    eb:50:b1:42:55:1a:fc:c4:5d:20:68:78:97:12:b5:
    12:65:de:f5:9b:10:fa:3e:30:2e:f2:30:f2:bd:73:
    77:5c:43:11:c1:07:0a:d0:49:c0:01:d4:0a:ae:ad:
    10:e0:99:84:93:79:23:50:e9:78:a2:c5:35:83:67:
    0f:d7:66:0e:31:71:f3:f9:0e:64:18:a5:b8:f6:2a:
    be:31:3c:8c:a6:99:fa:7d:8a:b4:84:c5:0a:85:3b:
    e7:b9:2d:a9:44:77:54:1e:d2:96:d5:2c:aa:d8:97:
    17:78:5a:13:51:60:22:04:19:78:59:9b:0c:02:d3:
    b3:f9:94:17:33:17:38:90:28:7c:72:98:a9:dc:e8:
    db:f7
G:    2 (0x2)
```

### Step 4: Generate Bob's Private Key

```bash
openssl genpkey -paramfile dhparams.pem -out bob_dh_priv.pem
```

### Step 5: Extract Bob's Public Key

```bash
openssl pkey -in bob_dh_priv.pem -pubout -out bob_dh_pub.pem
```

Verify:

```bash
openssl pkey -in bob_dh_pub.pem -pubin -text -noout
```

Output:

```bash
DH Public-Key: (2048 bit)
public-key:
    00:8b:27:5b:17:87:03:9c:1c:4e:a4:55:d9:46:11:
    84:03:a3:b4:38:ee:a7:5a:c9:33:17:3b:3a:a9:4c:
    59:e7:f7:62:45:30:f3:6f:75:5e:3b:96:dc:d6:83:
    57:e4:d7:e2:4f:7e:3d:85:21:db:6b:27:d4:d2:c1:
    e5:0a:11:d4:66:6f:57:ef:e5:4b:2e:0f:0b:3f:e4:
    93:4c:0d:59:c4:43:5c:29:81:13:11:83:d6:d7:16:
    51:ae:c4:8a:20:a2:f2:b3:e1:e5:04:4c:7c:81:df:
    34:c0:20:8c:66:bb:0e:28:58:87:db:5c:9d:15:54:
    c6:75:b9:b1:2e:ec:ce:b6:fc:8f:55:64:62:ab:03:
    72:77:15:84:f3:ce:a3:5d:6b:62:31:75:6f:36:ad:
    6e:9a:23:2b:91:f6:10:d4:12:b3:da:12:2e:70:56:
    98:10:51:7a:f1:eb:f2:c5:b0:34:3c:b0:f4:ce:02:
    92:06:1b:9e:28:4e:d5:cd:7a:d2:28:17:94:a3:e0:
    2e:25:b8:a4:a7:7d:aa:68:c2:c9:6e:54:c2:c9:ca:
    57:b6:b1:8d:24:5d:6d:db:95:ac:05:1b:4f:07:80:
    96:5e:ac:7e:7a:81:62:1b:e3:15:34:b4:92:43:d1:
    01:62:d7:5b:5a:38:11:31:4a:b9:3b:e3:61:32:73:
    4a:75
P:   
    00:e9:33:8c:d0:82:a0:83:46:29:f9:90:3a:ad:a2:
    55:c6:85:f1:a8:07:70:9a:56:d7:15:43:b2:c2:e0:
    08:86:5e:7c:95:ac:fb:2a:51:c5:22:53:f3:a9:15:
    fa:ff:cb:47:bc:79:13:c0:07:48:19:d4:ce:cb:5c:
    e5:3c:64:fa:16:08:88:49:fb:d6:24:fc:2e:fd:36:
    3f:11:df:d4:25:ce:a3:f0:1c:c4:f1:d6:c0:91:3b:
    30:64:c7:51:52:66:e8:43:1e:ed:8a:6f:df:5c:c1:
    46:6d:0c:21:f4:e7:48:6b:86:aa:dc:80:5d:f4:bc:
    eb:50:b1:42:55:1a:fc:c4:5d:20:68:78:97:12:b5:
    12:65:de:f5:9b:10:fa:3e:30:2e:f2:30:f2:bd:73:
    77:5c:43:11:c1:07:0a:d0:49:c0:01:d4:0a:ae:ad:
    10:e0:99:84:93:79:23:50:e9:78:a2:c5:35:83:67:
    0f:d7:66:0e:31:71:f3:f9:0e:64:18:a5:b8:f6:2a:
    be:31:3c:8c:a6:99:fa:7d:8a:b4:84:c5:0a:85:3b:
    e7:b9:2d:a9:44:77:54:1e:d2:96:d5:2c:aa:d8:97:
    17:78:5a:13:51:60:22:04:19:78:59:9b:0c:02:d3:
    b3:f9:94:17:33:17:38:90:28:7c:72:98:a9:dc:e8:
    db:f7
G:    2 (0x2)
```

### Step 6: Derive the Shared Secret (Alice's Side)

Alice uses her private key and Bob's public key to compute the shared secret:

```bash
openssl pkeyutl -derive -inkey alice_dh_priv.pem -peerkey bob_dh_pub.pem -out alice_secret.bin
```

### Step 7: Derive the Shared Secret (Bob's Side)

Bob uses his private key and Alice's public key to compute the shared secret:

```bash
openssl pkeyutl -derive -inkey bob_dh_priv.pem -peerkey alice_dh_pub.pem -out bob_secret.bin
```

### Step 8: Compare the Two Secrets

```bash
❯ diff alice_secret.bin bob_secret.bin && echo "MATCH: Shared secrets are identical"
MATCH: Shared secrets are identical
```

---

## Part 2 - The Explanation

Imagine Alice and Bob want to agree on a secret number, but they can only talk in a room where Eve is listening to every word. They use a mathematical trick: Alice picks a secret color of paint and mixes it with a public base color, then sends the mixed pot to Bob. Bob does the same with his own secret color. Now Alice takes Bob's mixed pot and adds her secret color. Bob takes Alice's mixed pot and adds his secret color. Both pots now contain the public base color plus both secret colors, so they are identical. Eve saw the two mixed pots traveling across the room, but to separate the secret color back out of a mixture is mathematically infeasible—like unmixing paint. So Alice and Bob end up with the same shared secret (the combined paint color), even though neither ever sent their secret color directly. In the OpenSSL simulation, Alice's private key is her secret paint, her public key is the mixed pot she sends to Bob, and the derived shared secret is the final color they both arrive at independently. Eve captured the public parameters, Alice's public key, and Bob's public key, but without either private key, she cannot compute the shared secret—this is the difficulty of the discrete logarithm problem.

---

## Part 3 - The MITM Attack

### How a Man-in-the-Middle Attack Defeats Plain Diffie-Hellman

Plain Diffie-Hellman has no authentication: Alice has no way to verify that the public key she received actually came from Bob, and vice versa. An attacker (Eve) positioned on the network path can intercept Alice's public key and send her own public key to Bob instead, then intercept Bob's public key and send a different public key to Alice. Eve now performs two separate DH exchanges—one with Alice and one with Bob—and holds two different shared secrets. Alice thinks she is encrypting to Bob, but she is actually encrypting to Eve, who decrypts the traffic, reads it, re-encrypts it to Bob, and neither party knows they are compromised. This is why Diffie-Hellman alone is necessary but not sufficient for secure communication.

### Mapping to MedDefense

For the VPN tunnel between Central and Westside, if the IPSec configuration relies on DH key exchange without certificate-based authentication, an attacker on the network path (for example, compromising the consumer-grade Netgear Nighthawk router at the Westside site) could intercept the DH exchange and establish two separate encrypted tunnels—one to the Central FortiGate and one to the Westside router. The attacker would then be able to decrypt all VPN traffic between the sites, including EHR database replication, billing data transfers, and Active Directory authentication traffic, read or modify it in plaintext, and re-encrypt it to the other side without either endpoint detecting the interception.

### How Certificates Prevent MITM

Certificates solve this problem by binding a public key to a verified identity. When the FortiGate at Central presents its certificate to the Westside router, the certificate contains the FortiGate's public key and is digitally signed by a Certificate Authority (CA) that both parties trust. Eve cannot forge a certificate for "Central FortiGate" because she does not possess the CA's private signing key. When Westside verifies the certificate's CA signature and confirms the identity, it knows the public key genuinely belongs to the Central FortiGate, not to Eve. If Eve substitutes her own public key during the exchange, the certificate validation fails, the connection is refused, and the MITM attack is prevented. This is why every TLS connection and every VPN tunnel at MedDefense must use certificate-based authentication, not anonymous DH.
