# Algorithms & Patterns Coverage

Full reference of weak/broken cryptographic algorithms organised by category.

> **v1.0 scope:** Rules 1 (`WeakHashAlgorithm`), 4 (`InsecureRandom`), 6 (`WeakPasswordHash`).
> Rules covering ciphers, cipher modes, and key sizes are on the roadmap.

---

## 1. Broken Hashing Algorithms — `crypto:WeakHashAlgorithm` (v1.0)

| Algorithm | Reason | Skip in non-security context? |
|-----------|--------|--------------------------|
| MD5 | Collision attacks, preimage attacks | Yes — cache keys, dedup, ETags |
| SHA-1 | SHAttered collision (2017) | Yes — same as MD5 |
| SHA-0 | Predecessor to SHA-1, broken | No |
| MD4 | Weaker than MD5 | Rarely legitimate |
| MD2 | Very old, completely broken | No |
| CRC32 / CRC16 | Not cryptographic — misused as integrity check | Yes — non-security checksums |

### Java / Kotlin API Patterns to Detect

```java
// JDK
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

## 2. Broken Symmetric Ciphers — `crypto:BrokenCipher` (roadmap)

| Algorithm | Reason | Context escape? |
|-----------|--------|--------------------------|
| DES | 56-bit key, brute-forceable | No |
| 3DES / Triple-DES | Sweet32 attack, NIST deprecated (2017) | No |
| RC4 | Keystream bias, broken in WEP/TLS | No |
| RC2 | Weak, small variable key sizes | No |
| Blowfish | 64-bit block size → Sweet32 attack | Rarely |

### Java / Kotlin API Patterns to Detect

```java
Cipher.getInstance("DES/...")
Cipher.getInstance("DESede/...")  // 3DES
Cipher.getInstance("RC4")
Cipher.getInstance("RC2/...")
Cipher.getInstance("Blowfish/...")
```

---

## 3. Weak Cipher Modes — `crypto:InsecureCipherMode` (roadmap)

| Mode | Reason |
|------|--------|
| ECB | No diffusion — identical blocks produce identical ciphertext |
| CBC with hardcoded/zero IV | Predictable IV breaks semantic security |
| CBC without padding validation | Padding oracle attack vector |

### Java / Kotlin API Patterns to Detect

```java
Cipher.getInstance("AES/ECB/...")
Cipher.getInstance("DES/ECB/...")
Cipher.getInstance("AES/CBC/NoPadding")  // flag if IV is hardcoded/zeroed
```

---

## 4. Weak Asymmetric / Key Sizes — `crypto:WeakKeySize` (roadmap)

| Issue | Flag Threshold |
|-------|---------------|
| RSA key size | < 2048 bits |
| DSA key size | < 2048 bits |
| EC weak curves | < 256-bit curves (`secp112r1`, `secp128r1`, `prime192v1`) |
| RSA with PKCS1v1.5 padding | Flag — prefer OAEP (Bleichenbacher attack) |

### Java / Kotlin API Patterns to Detect

```java
KeyPairGenerator.getInstance("RSA"); kpg.initialize(1024)  // key size < 2048
new RSAKeyGenParameterSpec(1024, ...)
ECGenParameterSpec("secp112r1")
ECGenParameterSpec("secp128r1")
Cipher.getInstance("RSA/ECB/PKCS1Padding")
```

---

## 5. Insecure Randomness — `crypto:InsecureRandom` (v1.0)

| What | Reason | Skip in non-security context? |
|------|--------|--------------------------|
| `java.util.Random` | Not a CSPRNG | Yes — game logic, shuffling, non-security |
| `Math.random()` | Not a CSPRNG | Yes — same |
| `SecureRandom` with fixed seed | Deterministic output | No — always flag |

### Java / Kotlin API Patterns to Detect

```java
new Random()                // flag only if output used in security context
Math.random()               // flag only if output used in security context
new SecureRandom(fixedSeed) // always flag
```

---

## 6. Password Hashing Anti-Patterns — `crypto:WeakPasswordHash` (v1.0)

| Pattern | Issue |
|---------|-------|
| Any general hash (MD5, SHA-256, SHA-512) applied directly to a password | Missing work factor |
| PBKDF2 with iteration count < 600,000 | Too fast — insufficient work factor (OWASP 2025) |
| Unsalted password hashes | Rainbow table attacks |

### Java / Kotlin API Patterns to Detect

```java
// Hashing password directly — detect when "password" is in the input variable name
MessageDigest.getInstance("SHA-256").digest(password.getBytes())

// PBKDF2 with low iteration count (threshold: 600,000 per OWASP 2025)
new PBEKeySpec(password, salt, 1000, keyLength)  // Noncompliant — < 600,000
new PBEKeySpec(password, salt, 600_000, keyLength)  // Compliant
```

---

## Priority Tiers Summary

### v1.0 — In Scope
- MD5, SHA-1, SHA-0, MD4 in security contexts (`WeakHashAlgorithm`)
- `Math.random()` / `java.util.Random` in security contexts (`InsecureRandom`)
- Fixed-seed `SecureRandom` (`InsecureRandom`)
- SHA-256/SHA-512 applied directly to passwords (`WeakPasswordHash`)
- PBKDF2 < 600,000 iterations (`WeakPasswordHash`)
- Unsalted password hashes (`WeakPasswordHash`)

### Roadmap — Not in v1.0
- DES, 3DES, RC4, RC2 (`BrokenCipher`)
- ECB mode, CBC with hardcoded IV (`InsecureCipherMode`)
- RSA < 2048 bits, weak EC curves (`WeakKeySize`)
