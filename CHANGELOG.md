# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Planned
- Replace regex sensor with JavaParser-based AST sensor to reduce false positives while keeping Phase 1 compatibility
- Kotlin language support

---

## 2025-03-10 — Regex Sensor Fallback

### Added
- `CryptoSensor`: regex-based fallback sensor using only `sonar-plugin-api` types (`8d72129`)
  - Covers all three rules: `WeakHashAlgorithm`, `InsecureRandom`, `WeakPasswordHash`
  - Runs in SonarQube Phase 1 — no dependency on sonar-java classloading
  - Context-aware filtering via method name/parameter keyword scanning
- Aligned dependency versions to SonarQube 25.1 LTA (`sonar-plugin-api` 11.0.0.2664, `java-frontend` 8.8.0.37665)

### Fixed
- `JavaCheckRegistrar` registration guarded via `Class.forName()` to prevent `ClassNotFoundException` during Phase 1 loading (`850d139`)
- `BeanDefinitionRegistryPostProcessor` approach removed — caused `ClassNotFoundException` in Phase 1 (`5fd8429`)
- Plugin `define()` guarded to handle missing sonar-java gracefully (`54a0d2f`)

## 2025-03-09 — Detection Logic

### Added
- Full detection logic for all three rules (`4a1632c`):
  - `WeakHashAlgorithmRule`: MD5, SHA-1, MD2, MD4 via MessageDigest, DigestUtils, Guava Hashing, BouncyCastle
  - `InsecureRandomRule`: `new Random()` in security context, `Math.random()` in security context, fixed-seed `SecureRandom`, `setSeed()`
  - `WeakPasswordHashRule`: hash on password variables, PBEKeySpec with < 600,000 iterations
- `ContextScorer` utility for heuristic security context detection
- Unit tests with `CheckVerifier` and sample files for all three rules
- `requirePlugins` format corrected to `java:8.9.0.37768` (`99d1ac6`)
- `pluginApiMinVersion` used instead of deprecated `sonarQubeMinVersion` (`f7e250b`)

## 2025-03-07 — Project Skeleton

### Added
- Monorepo skeleton with parent POM, `common/` and `plugin-java/` modules (`ab70779`)
- Three rule stubs: `WeakHashAlgorithm`, `InsecureRandom`, `WeakPasswordHash`
- Rule metadata (HTML descriptions, JSON specs) for all three rules
- `CryptoRulesPlugin`, `CryptoRulesDefinition`, `JavaCheckRegistrar`, `RulesList`
- GitHub Actions workflow for automated pre-release builds
- Design docs: `rule-design.md`, `detection-strategy.md`, `algorithms-coverage.md`, `compatibility.md`
- Docker Compose test configuration (`docker-compose.test.yml`)
- Initial commit (`913c736`)
