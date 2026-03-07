# SonarQube Version Compatibility

## Target Versions

| SonarQube | Internal Release | Plugin API | sonar-java |
|-----------|-----------------|------------|------------|
| **2025.1 LTA** (current) | `25.1.0.102122` | ~11.1.x | ~8.9.x |
| **2026.1 LTA** (upcoming) | `26.1.0.118079` | ~13.4.x | ~8.22.x |

---

## Build Strategy

Build against the **lower API (11.x)** and declare the minimum version in the plugin manifest.

### pom.xml
```xml
<properties>
    <!-- Minimum SonarQube version supported -->
    <sonar.pluginApiMinVersion>11.1.0.2693</sonar.pluginApiMinVersion>

    <!-- Build against lower API for max compatibility -->
    <sonarPluginApi.version>11.1.0.2693</sonarPluginApi.version>

    <!-- sonar-java plugin API — stable across both SQ versions -->
    <sonarJava.version>8.9.0.37768</sonarJava.version>
</properties>

<dependencies>
    <dependency>
        <groupId>org.sonarsource.api.plugin</groupId>
        <artifactId>sonar-plugin-api</artifactId>
        <version>${sonarPluginApi.version}</version>
        <scope>provided</scope>
    </dependency>
    <dependency>
        <groupId>org.sonarsource.java</groupId>
        <artifactId>sonar-java-plugin</artifactId>
        <version>${sonarJava.version}</version>
        <scope>provided</scope>
    </dependency>
</dependencies>
```

---

## Breaking Changes Between 2025.1 and 2026.1

### Plugin API 12.0 (May 2025)
- **Removed:** Deprecated Issue Workflow transitions and statuses (`Issue.transition()`, old workflow status APIs)
- **Added:** Hidden files analysis support
- **Impact on crypto rules:** None — detection rules use `NewIssue` / `NewIssueLocation`, not workflow transitions

### Plugin API 13.0 (July 2025)
- Internal/structural changes only
- **Impact on crypto rules:** None expected

---

## Safe APIs to Use (Stable Across Both Versions)

These APIs have been stable and are safe to depend on:

```java
// Rule definition
IssuableSubscriptionVisitor
MethodInvocationTree
LiteralTree
Tree.Kind

// Issue reporting
NewIssue
NewIssueLocation
SensorContext

// Rule metadata
RuleKey
RuleStatus
```

## APIs to Avoid

```java
// Removed in Plugin API 12.0 — do not use
Issue.transition(...)
WorkflowTransition
// Any deprecated issue status/workflow APIs
```

---

## Testing Matrix

Test the plugin JAR against both SonarQube versions using Docker before release.

```yaml
# docker-compose.test.yml
services:
  sonarqube-2025:
    image: sonarqube:25.1-community
    ports:
      - "9000:9000"
    volumes:
      - ./build/libs/plugin.jar:/opt/sonarqube/extensions/plugins/plugin.jar

  sonarqube-2026:
    image: sonarqube:26.1-community
    ports:
      - "9001:9000"
    volumes:
      - ./build/libs/plugin.jar:/opt/sonarqube/extensions/plugins/plugin.jar
```

Run scans against a sample project with known crypto violations on both instances and verify issues are raised correctly.

---

## Java Version Requirements

| SonarQube | Minimum Java |
|-----------|-------------|
| 2025.1 LTA | Java 17 |
| 2026.1 LTA | Java 17+ (verify at upgrade time) |

Build the plugin with **Java 17** to ensure compatibility with both.
