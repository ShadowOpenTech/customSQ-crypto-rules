# Architecture

## Overview

This is a custom SonarQube plugin that detects weak cryptographic practices in Java code, raising them as **Vulnerabilities** with context-aware severity. It is structured as a Maven multi-module project targeting SonarQube 25.1 LTA and above.

## Module Structure

```
customSQ-crypto-rules/
├── pom.xml                     ← Parent POM (Java 17, dependency management)
├── common/                     ← Shared rule metadata (reserved for multi-language future)
│   └── pom.xml
└── plugin-java/                ← The actual SonarQube plugin JAR
    ├── pom.xml                 ← sonar-plugin packaging, declares plugin entry point
    └── src/
        ├── main/java/com/sot/sonar/crypto/
        │   ├── CryptoRulesPlugin.java      ← Plugin entry point (implements Plugin)
        │   ├── CryptoRulesDefinition.java   ← Registers rules in the "crypto" repository
        │   ├── CryptoSensor.java            ← Regex-based sensor (active detection path)
        │   ├── JavaCheckRegistrar.java       ← AST-based check registration (currently blocked)
        │   ├── RulesList.java               ← Central list of all rule classes
        │   └── rules/
        │       ├── WeakHashAlgorithmRule.java
        │       ├── InsecureRandomRule.java
        │       └── WeakPasswordHashRule.java
        │   └── util/
        │       └── ContextScorer.java       ← Shared heuristic for security context detection
        └── main/resources/org/sonar/l10n/java/rules/crypto/
            ├── WeakHashAlgorithm.html / .json
            ├── InsecureRandom.html / .json
            └── WeakPasswordHash.html / .json
```

## Two Detection Layers

The plugin contains **two independent detection mechanisms** for the same three rules. This is not redundancy by design — it is a workaround for a SonarQube classloading limitation.

### Layer 1: AST-Based Checks (sonar-java API)

**Classes:** `WeakHashAlgorithmRule`, `InsecureRandomRule`, `WeakPasswordHashRule`
**API:** Extends `IssuableSubscriptionVisitor` from sonar-java's `java-frontend`
**Registration:** `JavaCheckRegistrar` implements `CheckRegistrar`

These checks visit the parsed AST (Abstract Syntax Tree) and have access to:
- Fully-qualified type resolution (e.g., knows `md` is `java.security.MessageDigest`)
- Method invocation trees with resolved symbols
- Parent/child tree traversal for context scoring via `ContextScorer`

**Status: Works in unit tests only.** The `java-checks-testkit` provides `CheckVerifier` which validates these rules against sample files in `src/test/resources/`. All three rules pass their tests.

**Why they don't run in production:** See [Phase 1 / Phase 2 Loading Problem](#phase-1--phase-2-loading-problem) below.

### Layer 2: Regex-Based Sensor (sonar-plugin-api only)

**Class:** `CryptoSensor` implements `Sensor`
**API:** Uses only `sonar-plugin-api` types — no sonar-java dependency

This sensor reads each `.java` file as plain text and applies regex patterns line-by-line. It includes:
- Compiled `Pattern` constants for each detection case
- A `MethodContext` inner class that scans backwards from the flagged line to find the enclosing method declaration
- Security/non-security keyword lists for context-aware filtering (mirrors `ContextScorer` logic)

**Status: Active detection path.** This is what actually raises issues in production SonarQube scans.

**Trade-offs:**
- No type resolution — cannot distinguish `java.util.Random` from a custom `Random` class
- Line-based — cannot detect patterns spanning multiple lines
- Regex-based context detection is less accurate than AST-based `ContextScorer`
- Can produce false positives (e.g., a method named `rollDice()` containing `new Random()` near a variable named `token`)

## Phase 1 / Phase 2 Loading Problem

This is the key architectural constraint that explains why the regex sensor exists.

### How SonarQube Loads Plugins

SonarQube (26.x and to some extent 25.x) loads plugins in two phases:

1. **Phase 1:** External/third-party plugins are loaded. Their `Plugin.define()` runs, and all registered extensions (sensors, rules definitions) are instantiated.
2. **Phase 2:** Built-in plugins load, including **sonar-java**. sonar-java creates its own Spring context and looks for `CheckRegistrar` beans within that context.

### The Problem

Our plugin registers `JavaCheckRegistrar` in Phase 1, but sonar-java's Spring context is only created in Phase 2. sonar-java's `SonarComponents` class collects `CheckRegistrar` instances via Spring dependency injection — but it only sees beans registered within its own Phase 2 context, not beans from external plugins registered in Phase 1.

Result: `JavaCheckRegistrar` is instantiated but **never injected** into `SonarComponents`, so the AST-based checks are never executed.

### Approaches Tried and Failed

| Approach | Result |
|---|---|
| `BeanDefinitionRegistryPostProcessor` to inject into sonar-java's context | `ClassNotFoundException` — sonar-java classes not available in Phase 1 |
| `basePlugin=java` manifest entry to load as a sonar-java extension | `NullPointerException` in plugin loader |
| ServiceLoader SPI (`META-INF/services/CheckRegistrar`) | sonar-java does not use ServiceLoader for check discovery |
| `Startable` interface to defer registration | Still runs in Phase 1 context |

### Current Workaround

`CryptoRulesPlugin.define()` wraps the `JavaCheckRegistrar` registration in a try/catch:

```java
try {
    context.addExtension(
        Class.forName("com.sot.sonar.crypto.JavaCheckRegistrar",
            true, getClass().getClassLoader()));
} catch (ClassNotFoundException | NoClassDefFoundError ignored) {
    // sonar-java not available yet in this loading phase
}
```

This prevents a hard crash. The regex-based `CryptoSensor` runs unconditionally in Phase 1 and provides the actual detection.

### Future Resolution

If sonar-java adds ServiceLoader-based `CheckRegistrar` discovery (or another extension point for external plugins), the AST-based checks could replace the regex sensor. Until then, the regex sensor is the production path.

## Context Scoring

Both detection layers implement context-aware severity using keyword heuristics:

**Security keywords** (escalate to CRITICAL): `password`, `passwd`, `pwd`, `auth`, `authenticate`, `login`, `token`, `secret`, `credential`, `session`, `encrypt`, `decrypt`, `cipher`, `sign`, `verify`, `hmac`, `salt`, `nonce`, `apikey`

**Non-security keywords** (skip entirely): `etag`, `cache`, `cacheKey`, `checksum`, `fingerprint`, `uuid`, `dedup`, `deduplicate`, `slug`, `filename`

- AST layer: `ContextScorer.score(Tree node)` walks up the AST collecting names from enclosing variables and methods.
- Regex layer: `CryptoSensor.findEnclosingMethod()` scans backwards through lines to find the nearest method declaration and checks its name and parameters.

Non-security keywords take precedence over mixed signals — if both are present, the issue is skipped.

## Rule Metadata

Each rule requires two resource files in `src/main/resources/org/sonar/l10n/java/rules/crypto/`:

- **`<RuleKey>.html`** — The description shown in SonarQube's rule browser. Includes noncompliant/compliant code examples and CWE/OWASP references.
- **`<RuleKey>.json`** — Metadata: title, type (`VULNERABILITY`), default severity, remediation cost, and tags.

These are loaded by `RuleMetadataLoader` from `sonar-analyzer-commons` in `CryptoRulesDefinition`.

## CI / CD

A GitHub Actions workflow (`.github/workflows/build-prerelease.yml`) runs on every push to `master`:
1. Builds the plugin JAR (`mvn clean package -pl plugin-java -am -DskipTests`)
2. Creates/replaces a `dev-latest` pre-release on GitHub with the built JAR

## Testing

### Unit Tests (AST-based rules)

Each rule has a corresponding test using sonar-java's `CheckVerifier`:
- `WeakHashAlgorithmRuleTest` + `WeakHashAlgorithmSamples.java`
- `InsecureRandomRuleTest` + `InsecureRandomSamples.java`
- `WeakPasswordHashRuleTest` + `WeakPasswordHashSamples.java`

Sample files use `// Noncompliant` annotations to mark expected issue lines.

### Integration Testing (regex sensor)

The regex sensor is tested by deploying the JAR to a SonarQube instance and running `sonar-scanner` against a test project:
- Test project at `/Users/cyberdevil/codeWorkspace/customSQ-crypto-rules-test`
- Docker Compose test setup in `docker-compose.test.yml`
