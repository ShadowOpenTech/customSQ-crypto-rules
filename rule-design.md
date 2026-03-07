# Rule Design

## Proposed Rule Set

Rather than one monolithic rule, split into focused rules that map cleanly to SonarQube's issue taxonomy.

---

## Rule 1: Weak Hash Algorithm Usage

**Rule key:** `crypto:WeakHashAlgorithm`
**Type:** Vulnerability
**Default severity:** MAJOR (context-adjusted, see below)

### Detects
- MD5, SHA-1, SHA-0, MD4, MD2 via `MessageDigest.getInstance()`
- Library equivalents: Guava `Hashing.md5()`, Apache `DigestUtils.md5()`, BouncyCastle `new MD5Digest()`

### Severity Adjustment
| Context signals | Severity |
|----------------|----------|
| Security keywords in scope (password, auth, token, secret) | CRITICAL |
| No clear context | MAJOR |
| Non-security keywords in scope (cache, etag, uuid, dedup) | INFO |
| `@SafeWeakHash` annotation or `// safe-hash:` comment | Suppressed |

### Message
> `MD5` is a broken hash algorithm and must not be used for security purposes. If this is not security-sensitive (e.g. cache key, ETag), suppress with `@SafeWeakHash("reason")`.

---

## Rule 2: Broken Symmetric Cipher

**Rule key:** `crypto:BrokenCipher`
**Type:** Vulnerability
**Default severity:** CRITICAL

### Detects
- DES, 3DES/DESede, RC4, RC2, Blowfish via `Cipher.getInstance()`

### No context escape — always flag.

### Message
> `DES` is a broken cipher and must not be used. Use `AES/GCM/NoPadding` with a 256-bit key.

---

## Rule 3: Insecure Cipher Mode

**Rule key:** `crypto:InsecureCipherMode`
**Type:** Vulnerability
**Default severity:** CRITICAL

### Detects
- Any cipher using ECB mode: `Cipher.getInstance("AES/ECB/...")`, `Cipher.getInstance("DES/ECB/...")`
- CBC with hardcoded/zero IV (requires data flow to detect IV source)

### No context escape — always flag.

### Message
> ECB mode leaks data patterns. Use `AES/GCM/NoPadding` with a randomly generated IV/nonce.

---

## Rule 4: Insecure Randomness

**Rule key:** `crypto:InsecureRandom`
**Type:** Vulnerability
**Default severity:** MAJOR

### Detects
- `new Random()`, `Math.random()` where output is used in a security context
- `new SecureRandom(fixedSeed)` — always flag

### Severity Adjustment
| Context | Severity |
|---------|----------|
| Output used for token, session, key, salt, nonce | CRITICAL |
| Fixed seed `SecureRandom` | CRITICAL |
| No clear security context | INFO |

### Message
> `java.util.Random` is not cryptographically secure. Use `SecureRandom` for security-sensitive random values.

---

## Rule 5: Weak Asymmetric Key Size

**Rule key:** `crypto:WeakKeySize`
**Type:** Vulnerability
**Default severity:** CRITICAL

### Detects
- RSA or DSA key generation with size < 2048 bits
- EC curves with < 256-bit strength
- RSA with PKCS1v1.5 padding (`RSA/ECB/PKCS1Padding`)

### Message
> RSA key size of `1024` bits is insufficient. Use at least 2048 bits. Prefer `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`.

---

## Rule 6: Password Stored with Weak Hash

**Rule key:** `crypto:WeakPasswordHash`
**Type:** Vulnerability
**Default severity:** CRITICAL

### Detects
- `MessageDigest` applied to a variable named `password`, `passwd`, `pwd`, `credentials`
- PBKDF2 with iteration count < 100,000
- Unsalted hashes (no salt parameter near the hash call)

### Message
> Passwords must not be hashed with `SHA-256` directly. Use a password hashing function: `Argon2`, `bcrypt`, `scrypt`, or `PBKDF2` with >= 100,000 iterations and a random salt.

---

## Implementation Path

### Option A: Regex Pattern Rules (Quick Start)
- Available directly in SonarQube UI under "Rules > Create Rule"
- Limited to text/regex pattern matching
- No AST, no data flow
- Good for: catching `Cipher.getInstance("DES")`, `Hashing.md5()` etc.
- Not good for: key size checks, context disambiguation

### Option B: Custom Java Plugin (Full Power)
- Implement `IssuableSubscriptionVisitor` from `sonar-java` plugin API
- Full AST access via `MethodInvocationTree`, `LiteralTree`
- Can do basic data flow via `CheckVerifier`
- Required for: key size checks, IV analysis, context disambiguation
- Deployment: JAR dropped into `$SONARQUBE_HOME/extensions/plugins/`

### Option C: SonarQube SAST YAML Rules (Newer Versions)
- Available in SonarQube 10.x+
- Pattern-based with some taint support
- Middle ground between A and B

---

## Suppression Convention

```java
// Option 1: Annotation (preferred — self-documenting, reviewable)
@SafeWeakHash("ETag generation only — not used for authentication or data integrity")
public String computeETag(byte[] body) {
    return DigestUtils.md5Hex(body);
}

// Option 2: Inline comment
String cacheKey = DigestUtils.md5Hex(url); // safe-hash: cache key, not security-sensitive

// Option 3: SonarQube built-in (least preferred — no reason required)
String cacheKey = DigestUtils.md5Hex(url); // NOSONAR
```
