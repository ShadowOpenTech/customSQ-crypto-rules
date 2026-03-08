# customSQ-crypto-rules

Custom SonarQube plugin that detects weak and broken cryptographic practices in Java and Kotlin, raising them as **Vulnerabilities** (not Hotspots) with context-aware severity.

## Rules — v1.0

| Rule Key | Severity | Description |
|---|---|---|
| `crypto:WeakHashAlgorithm` | CRITICAL / MAJOR | MD5, SHA-1 and equivalents in security contexts |
| `crypto:InsecureRandom` | CRITICAL | `new Random()` in security contexts; fixed-seed `SecureRandom` |
| `crypto:WeakPasswordHash` | CRITICAL | General hash on password variable; PBKDF2 < 600k iterations; unsalted |

## Why not rely on built-in SonarQube rules?

| Built-in Rule | Gap |
|---|---|
| `java:S4790` (weak hash) | Security **Hotspot** only — no severity tiering, no BouncyCastle |
| `java:S2245` (PRNG) | Security **Hotspot** only — fixed-seed `SecureRandom` not covered |
| _(none)_ | No built-in rule for password hashing anti-patterns |

## Roadmap

### v1.x — Additional Java/Kotlin rules
- `crypto:BrokenCipher` — DES, 3DES, RC4, RC2, Blowfish
- `crypto:InsecureCipherMode` — ECB mode, CBC with hardcoded IV
- `crypto:WeakKeySize` — RSA/DSA < 2048 bits, weak EC curves

### v2.0+ — Additional languages (separate plugin modules, same repo)
- Python
- JavaScript / TypeScript
- C#

## Repository Structure

```
customSQ-crypto-rules/
├── pom.xml                  ← parent POM (multi-module)
├── common/                  ← shared rule metadata (HTML descriptions, JSON specs)
└── plugin-java/             ← Java + Kotlin plugin JAR
```

## Compatibility

| SonarQube | Status |
|---|---|
| 2025.1 LTA | Supported |
| 2026.1 LTA | Supported |

## Languages

| Language | Status |
|---|---|
| Java | v1.0 |
| Kotlin | v1.0 |
| Python | Roadmap |
| JavaScript / TypeScript | Roadmap |
| C# | Roadmap |

## Build

```bash
cd plugin-java
mvn clean package
# Output: plugin-java/target/crypto-rules-java-1.0.0.jar
```

## Install

Drop the JAR into `$SONARQUBE_HOME/extensions/plugins/` and restart SonarQube.

## Suppression

Use SonarQube's built-in `// NOSONAR` on the flagged line. No custom annotation or comment convention is supported.

## Files

- [rule-design.md](./rule-design.md) — Rule specs, severity tiers, detection patterns
- [detection-strategy.md](./detection-strategy.md) — Context disambiguation strategy
- [algorithms-coverage.md](./algorithms-coverage.md) — Full algorithm and API pattern reference
- [compatibility.md](./compatibility.md) — SonarQube version compatibility and build config
