# CLAUDE.md

## Project

Custom SonarQube plugin detecting weak cryptographic practices in Java. Monorepo with two modules: `common/` (shared metadata) and `plugin-java/` (the plugin JAR).

## Build Commands

```bash
# Build plugin JAR
mvn clean package -pl plugin-java -am

# Build without tests
mvn clean package -pl plugin-java -am -DskipTests

# Run all tests
mvn test

# Run single test
mvn test -pl plugin-java -Dtest=WeakHashAlgorithmRuleTest
```

## Key Architecture Decisions

- **Two detection layers exist**: AST-based rules (sonar-java API) work in tests but are blocked at runtime due to SonarQube's Phase 1/Phase 2 classloading. The regex-based `CryptoSensor` is the active production path. See `ARCHITECTURE.md` for details.
- **Do not remove the AST-based rules** — they serve as the reference implementation and are used in unit tests.
- **Do not remove the regex sensor** — it is the only detection path that works in production until the classloading issue is resolved.
- The planned replacement is a **JavaParser-based AST sensor** that runs in Phase 1 without sonar-java dependency.

## Conventions

- Java 17, no preview features
- Rule keys: PascalCase (e.g., `WeakHashAlgorithm`)
- Repository key: `crypto`
- All dependencies on `sonar-plugin-api` and `java-frontend` are `provided` scope
- Suppression: `// NOSONAR` only
- Issue messages must name the specific algorithm and suggest a compliant alternative
- Use `ContextScorer` for context-aware severity in AST rules; mirror keywords in `CryptoSensor` for regex layer

## Deploy & Test

```bash
# Copy JAR to SonarQube plugins dir and restart
cp plugin-java/target/crypto-rules-java-1.0.0-SNAPSHOT.jar /path/to/sonarqube/extensions/plugins/

# Docker-based testing
docker compose -f docker-compose.test.yml up -d

# Test project scan
cd /Users/cyberdevil/codeWorkspace/customSQ-crypto-rules-test
sonar-scanner -Dsonar.host.url=http://localhost:9000 -Dsonar.token=<token>
```

## File Locations

- Plugin entry point: `plugin-java/src/main/java/com/sot/sonar/crypto/CryptoRulesPlugin.java`
- Active sensor: `plugin-java/src/main/java/com/sot/sonar/crypto/CryptoSensor.java`
- Rule implementations: `plugin-java/src/main/java/com/sot/sonar/crypto/rules/`
- Rule metadata: `plugin-java/src/main/resources/org/sonar/l10n/java/rules/crypto/`
- Test samples: `plugin-java/src/test/resources/com/sot/sonar/crypto/rules/samples/`
