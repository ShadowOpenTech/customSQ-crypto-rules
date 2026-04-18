# Contributing

## Prerequisites

- **Java 17** (the plugin compile target)
- **Maven 3.8+**
- **SonarQube 25.1 LTA** or later (for integration testing)
- **Docker** (optional, for local SonarQube via `docker-compose.test.yml`)

## Build

```bash
# Full build (all modules)
mvn clean package

# Plugin JAR only (skips tests for speed)
mvn clean package -pl plugin-java -am -DskipTests
```

The output JAR is at `plugin-java/target/crypto-rules-java-1.0.0-SNAPSHOT.jar`.

## Run Tests

```bash
# All unit tests
mvn test

# Single rule test
mvn test -pl plugin-java -Dtest=WeakHashAlgorithmRuleTest
```

Tests use sonar-java's `CheckVerifier` and sample files in `plugin-java/src/test/resources/com/sot/sonar/crypto/rules/samples/`.

## Deploy Locally

1. Build the plugin JAR (see above).
2. Copy it to your SonarQube plugins directory:
   ```bash
   cp plugin-java/target/crypto-rules-java-1.0.0-SNAPSHOT.jar /path/to/sonarqube/extensions/plugins/
   ```
3. Restart SonarQube.
4. Activate the rules in a Quality Profile under the **"Custom Crypto Rules"** repository.
5. Run `sonar-scanner` against a test project.

If using Docker:

```bash
docker compose -f docker-compose.test.yml up -d
# Wait for SonarQube to start, then deploy and scan
```

## Project Structure

```
customSQ-crypto-rules/
├── common/         ← Shared metadata (reserved for multi-language support)
├── plugin-java/    ← The SonarQube plugin
│   ├── src/main/java/com/sot/sonar/crypto/
│   │   ├── CryptoRulesPlugin.java    ← Entry point
│   │   ├── CryptoRulesDefinition.java
│   │   ├── CryptoSensor.java         ← Regex sensor (active path)
│   │   ├── JavaCheckRegistrar.java    ← AST checks (blocked, see ARCHITECTURE.md)
│   │   ├── RulesList.java
│   │   ├── rules/                     ← AST-based rule implementations
│   │   └── util/ContextScorer.java    ← Security context heuristic
│   └── src/main/resources/            ← Rule HTML descriptions and JSON metadata
└── docs/
```

See [ARCHITECTURE.md](./ARCHITECTURE.md) for details on the dual detection layers and the Phase 1/Phase 2 loading issue.

## Adding a New Rule

### 1. Define the Rule Metadata

Create two files in `plugin-java/src/main/resources/org/sonar/l10n/java/rules/crypto/`:

- **`YourRuleKey.json`:**
  ```json
  {
    "title": "Short description of the rule",
    "type": "VULNERABILITY",
    "status": "ready",
    "remediation": {
      "func": "Constant/Issue",
      "constantCost": "30min"
    },
    "tags": ["cwe", "cryptography", "security", "owasp"],
    "defaultSeverity": "Major"
  }
  ```

- **`YourRuleKey.html`:** Description with noncompliant/compliant code examples and CWE/OWASP references. Follow the format of existing rule HTML files.

### 2. Implement the AST-Based Rule

Create `plugin-java/src/main/java/com/sot/sonar/crypto/rules/YourRule.java`:

```java
@Rule(key = "YourRuleKey")
public class YourRule extends IssuableSubscriptionVisitor {
    @Override
    public List<Tree.Kind> nodesToVisit() {
        return Arrays.asList(Tree.Kind.METHOD_INVOCATION);
    }

    @Override
    public void visitNode(Tree tree) {
        // Detection logic
        // Use ContextScorer.score(tree) for context-aware severity
    }
}
```

### 3. Register the Rule

Add the rule class to `RulesList.java` in both `getJavaChecks()` and `getCheckClasses()`.

### 4. Add Regex Detection to CryptoSensor

Add regex patterns and a `check*()` method in `CryptoSensor.java`. Wire it into `analyseFile()` with an `isActive()` guard.

### 5. Write Tests

- Create a sample file: `src/test/resources/com/sot/sonar/crypto/rules/samples/YourRuleSamples.java`
  - Mark expected issues with `// Noncompliant` comments
  - Include both compliant and noncompliant examples
- Create a test: `src/test/java/com/sot/sonar/crypto/rules/YourRuleTest.java`
  ```java
  class YourRuleTest {
      @Test
      void test() {
          CheckVerifier.newVerifier()
              .onFile("src/test/resources/com/sot/sonar/crypto/rules/samples/YourRuleSamples.java")
              .withCheck(new YourRule())
              .verifyIssues();
      }
  }
  ```

### 6. Update Documentation

- Add the rule to `rule-design.md` with patterns, severity tiers, and messages.
- Add API patterns to `algorithms-coverage.md`.
- Add an entry to the rule table in `README.md`.

## Coding Conventions

- **Java 17** — no preview features
- **No Lombok or annotation processors** — keep dependencies minimal for plugin classloading
- **`provided` scope** for `sonar-plugin-api` and `java-frontend` — these are supplied by SonarQube at runtime
- **Rule keys** use PascalCase (e.g., `WeakHashAlgorithm`)
- **Repository key** is `crypto` — all rules share this repository
- **Context scoring** — use `ContextScorer` for AST-based rules; mirror the keyword lists in `CryptoSensor` for the regex layer
- **Issue messages** should name the specific algorithm/API and suggest a compliant alternative
- **Suppression** — `// NOSONAR` only; do not add custom suppression mechanisms

## Version Alignment

When updating dependency versions, keep these in sync:

| Property | What it controls |
|---|---|
| `sonarPluginApi.version` (parent POM) | SonarQube Plugin API — must match `pluginApiMinVersion` in plugin-java POM |
| `sonarJavaFrontend.version` (parent POM) | sonar-java API — must match `requirePlugins` in plugin-java POM |
| `pluginApiMinVersion` (plugin-java POM) | Minimum SonarQube version declared in manifest |
| `requirePlugins` (plugin-java POM) | Minimum sonar-java version declared in manifest |

See [compatibility.md](./compatibility.md) for version compatibility details.
