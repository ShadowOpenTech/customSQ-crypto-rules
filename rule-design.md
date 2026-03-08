# Rule Design

## v1.0 Rule Set

Three rules targeting gaps in SonarQube's built-in Java security coverage.

---

## Rule 1: Weak Hash Algorithm Usage

**Rule key:** `crypto:WeakHashAlgorithm`
**Type:** Vulnerability
**Default severity:** MAJOR (context-adjusted)

### Detects

| Pattern | Library |
|---|---|
| `MessageDigest.getInstance("MD5/SHA-1/SHA1/SHA-0/MD4/MD2")` | JDK |
| `DigestUtils.md5()` `.md5Hex()` `.sha1()` `.sha1Hex()` | Apache Commons |
| `Hashing.md5()` `.sha1()` `.crc32()` | Guava |
| `new MD5Digest()` `new SHA1Digest()` `new MD4Digest()` | BouncyCastle |

### Severity Adjustment

Scans enclosing method name, parameter names, and variable names in scope (via `ContextScorer`):

| Signal | Severity |
|---|---|
| Security keywords present: `password`, `passwd`, `pwd`, `auth`, `token`, `secret`, `credential`, `sign`, `hmac` | **CRITICAL** |
| No clear context | **MAJOR** |
| Non-security keywords present: `etag`, `cache`, `cacheKey`, `checksum`, `fingerprint`, `uuid`, `dedup`, `slug` | **skip — no issue raised** |

Multiple keywords accumulate as a score — not a single-match binary.

### Message
> `MD5` is a broken hash algorithm. Use `SHA-256` or stronger. If this is for a non-security purpose, suppress with `// NOSONAR`.

### Suppression
`// NOSONAR` only.

---

## Rule 4: Insecure Randomness

**Rule key:** `crypto:InsecureRandom`
**Type:** Vulnerability
**Default severity:** MAJOR (context-adjusted)

### Detects

| Pattern | Condition |
|---|---|
| `new Random()` | Only when output flows to a security-context variable |
| `Math.random()` | Only when output flows to a security-context variable |
| `new SecureRandom(seed)` with any argument | **Always** — any fixed seed = deterministic output |

Security-context variables: named with `token`, `session`, `key`, `salt`, `nonce`, `secret`, `password`, `auth`.

### Severity Adjustment

| Context | Severity |
|---|---|
| Output assigned to security-context variable | **CRITICAL** |
| Fixed-seed `SecureRandom` | **CRITICAL** |
| No security context detected | **skip — no issue raised** |

### Message
> `java.util.Random` is not cryptographically secure. Use `SecureRandom` for security-sensitive values.
> `SecureRandom` must not be seeded with a fixed value — this makes output deterministic.

### Suppression
`// NOSONAR` only.

---

## Rule 6: Password Stored with Weak Hash

**Rule key:** `crypto:WeakPasswordHash`
**Type:** Vulnerability
**Default severity:** CRITICAL (always)

### Detects — 3 sub-patterns

**A — Any hash applied directly to a password variable:**

Triggers when `MessageDigest.getInstance(any)`, `DigestUtils.*`, or `Hashing.*` receives input from a variable named `password`, `passwd`, `pwd`, `credentials`, `credential`, `userPassword`.
Includes SHA-256 and SHA-512 — even strong general-purpose hashes are wrong for passwords.

**B — PBKDF2 with insufficient iterations:**

`new PBEKeySpec(password, salt, iterationCount, keyLength)` where `iterationCount` literal < **600,000**.
Threshold follows OWASP 2025 recommendation for PBKDF2-HMAC-SHA256.

**C — Unsalted hash on a password variable:**

`MessageDigest` on a password-named variable with no `salt` variable visible as input in the same call chain.

### Message
> Passwords must not be hashed with `SHA-256` directly. Use `Argon2`, `bcrypt`, `scrypt`, or `PBKDF2` with ≥ 600,000 iterations and a random salt.

### Suppression
`// NOSONAR` only.

---

## Implementation

**Approach:** Custom Java Plugin (Option B) — full AST access via `IssuableSubscriptionVisitor`.

- `MethodInvocationTree` for detecting API calls
- `LiteralTree` for string/numeric argument inspection
- `ContextScorer` utility for heuristic name analysis (shared by Rules 1 and 4)

**Deployment:** JAR dropped into `$SONARQUBE_HOME/extensions/plugins/`

---

## Future Rules — Roadmap

| Rule Key | Description |
|---|---|
| `crypto:BrokenCipher` | DES, 3DES, RC4, RC2, Blowfish via `Cipher.getInstance()` |
| `crypto:InsecureCipherMode` | ECB mode; CBC with hardcoded/zero IV |
| `crypto:WeakKeySize` | RSA/DSA < 2048 bits; weak EC curves; PKCS1v1.5 padding |
