# Algorithms & Patterns Coverage

Full list of weak/broken cryptographic algorithms to detect, organized by category.

---

## 1. Broken Hashing Algorithms

| Algorithm | Reason | Context Escape Possible? |
|-----------|--------|--------------------------|
| MD5 | Collision attacks, preimage attacks | Yes — cache keys, dedup, ETags |
| SHA-1 | SHAttered collision (2017) | Yes — same as MD5 |
| SHA-0 | Predecessor to SHA-1, broken | No |
| MD4 | Weaker than MD5 | Rarely legitimate |
| MD2 | Very old, completely broken | No |
| CRC32 / CRC16 | Not cryptographic — misused as integrity check | Yes — non-security checksums |

### Java API Patterns to Detect
```java
MessageDigest.getInstance("MD5")
MessageDigest.getInstance("SHA-1")
MessageDigest.getInstance("SHA1")
MessageDigest.getInstance("MD4")
MessageDigest.getInstance("SHA-0")

// Apache Commons
DigestUtils.md5(...)
DigestUtils.md5Hex(...)
DigestUtils.sha1(...)
DigestUtils.sha1Hex(...)

// Guava
Hashing.md5()
Hashing.sha1()
Hashing.crc32()

// BouncyCastle
new MD5Digest()
new SHA1Digest()
new MD4Digest()
```

---

## 2. Broken Symmetric Ciphers

| Algorithm | Reason | Context Escape Possible? |
|-----------|--------|--------------------------|
| DES | 56-bit key, brute-forceable | No |
| 3DES / Triple-DES | Sweet32 attack, NIST deprecated (2017) | No |
| RC4 | Keystream bias, broken in WEP/TLS | No |
| RC2 | Weak, small variable key sizes | No |
| Blowfish | 64-bit block size → Sweet32 attack | Rarely |

### Java API Patterns to Detect
```java
Cipher.getInstance("DES/...")
Cipher.getInstance("DESede/...")  // 3DES
Cipher.getInstance("RC4")
Cipher.getInstance("RC2/...")
Cipher.getInstance("Blowfish/...")
```

---

## 3. Weak Cipher Modes (Algorithm May Be Fine, Mode Is Not)

| Mode | Reason |
|------|--------|
| ECB | No diffusion — identical blocks produce identical ciphertext |
| CBC with hardcoded/zero IV | Predictable IV breaks semantic security |
| CBC without padding validation | Padding oracle attack vector |

### Java API Patterns to Detect
```java
Cipher.getInstance("AES/ECB/...")
Cipher.getInstance("DES/ECB/...")
Cipher.getInstance("AES/CBC/NoPadding")  // flag if IV is hardcoded/zeroed
```

ECB mode is arguably a higher priority flag than weak algorithms — `AES/ECB` is widely misunderstood as "safe" because AES is mentioned.

---

## 4. Weak Asymmetric / Key Sizes

| Issue | Flag Threshold |
|-------|---------------|
| RSA key size | < 2048 bits |
| DSA key size | < 2048 bits |
| EC weak curves | < 256-bit curves (`secp112r1`, `secp128r1`, `prime192v1`) |
| RSA with PKCS1v1.5 padding | Flag — prefer OAEP (Bleichenbacher attack) |

### Java API Patterns to Detect
```java
KeyPairGenerator.getInstance("RSA"); kpg.initialize(1024)  // key size < 2048
new RSAKeyGenParameterSpec(1024, ...)
ECGenParameterSpec("secp112r1")
ECGenParameterSpec("secp128r1")
Cipher.getInstance("RSA/ECB/PKCS1Padding")  // prefer OAEPWithSHA-256AndMGF1Padding
```

---

## 5. Insecure Randomness (in Security Contexts)

| What | Reason | Context Escape Possible? |
|------|--------|--------------------------|
| `java.util.Random` | Not a CSPRNG | Yes — game logic, shuffling, non-security |
| `Math.random()` | Not a CSPRNG | Yes — same |
| `SecureRandom` with fixed seed | Deterministic output | No |

Same disambiguation challenge as MD5 — `Math.random()` for shuffling a playlist is fine; for generating a session token it is not.

### Java API Patterns to Detect
```java
new Random()               // flag if output used in security context
Math.random()              // flag if output used in security context
new SecureRandom(fixedSeed) // always flag
```

---

## 6. Password Hashing Anti-Patterns

These deserve their own sub-rule distinct from general weak hash detection.

| Pattern | Issue |
|---------|-------|
| Any general hash (MD5, SHA-256, SHA-512) applied directly to a password | Missing work factor — should use Argon2, bcrypt, scrypt, PBKDF2 |
| PBKDF2 with iteration count < 100,000 | Too fast — insufficient work factor |
| Unsalted password hashes | Rainbow table attacks |

### Java API Patterns to Detect
```java
// Hashing password directly — detect when "password" is in the input variable name
MessageDigest.getInstance("SHA-256").digest(password.getBytes())

// PBKDF2 with low iteration count
new PBEKeySpec(password, salt, 1000, keyLength)  // < 100000 iterations
```

---

## Priority Tiers Summary

### Always Flag (No Legitimate Use)
- DES, 3DES, RC4, RC2
- ECB mode (any cipher)
- RSA < 2048 bits
- Fixed-seed `SecureRandom`
- `SSLv3`, `TLSv1.0`, `TLSv1.1`

### Flag with Context Disambiguation
- MD5, SHA-1, SHA-0, MD4
- CRC32 used as integrity/hash
- `Math.random()` / `java.util.Random`
- Blowfish

### Flag in Password-Specific Context Only
- SHA-256/SHA-512 applied directly to passwords
- PBKDF2 with low iteration count
- Unsalted hashes
