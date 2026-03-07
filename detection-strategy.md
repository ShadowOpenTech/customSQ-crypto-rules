# Detection Strategy

## The Core Problem

Static analysis cannot always determine *intent* from syntax alone. The goal is to use contextual signals to reduce false positives and prioritize true security risks.

---

## Strategy 1: Heuristic Name Analysis (Easiest, Imperfect)

Scan surrounding variable names, method names, parameter names, and class names for keywords.

### Flag / Escalate if near:
- `password`, `passwd`, `pwd`
- `auth`, `authenticate`, `login`
- `token`, `secret`, `credential`
- `encrypt`, `decrypt`, `cipher`
- `sign`, `verify`, `hmac`
- `hash`, `digest` (in a security context)

### Suppress / Downgrade if near:
- `etag`, `cache`, `cacheKey`
- `fingerprint`, `checksum`
- `uuid`, `random`, `randomId`
- `deduplicate`, `dedup`
- `slug`, `id`, `filename`

Accumulate signals as a score rather than a binary match — multiple security-context keywords increase confidence.

---

## Strategy 2: Data Flow Analysis (Harder, More Accurate)

Track where the hash output is used:

| Output destination | Action |
|--------------------|--------|
| Stored in `password` field/column | Flag |
| Compared in an auth/login check | Flag |
| Set as `Cache-Control` / `ETag` header | Suppress |
| Used as a database row key or cache key | Suppress |
| Returned from method named `generateId` / `randomSlug` | Suppress |

Requires taint/flow analysis — supported in SonarQube's Java plugin via `CheckVerifier` + flow tracking.

---

## Strategy 3: Explicit Escape Hatch (Pragmatic)

Allow developers to mark legitimate uses explicitly:

```java
// safe-hash: used for cache key only, not security
MessageDigest.getInstance("MD5").digest(content);
```

Or via a custom annotation:
```java
@SafeWeakHash("Used for ETag generation only, not security-sensitive")
public String generateETag(byte[] content) { ... }
```

The annotation approach is preferable — it's searchable, reviewable in PRs, and self-documenting.

SonarQube's built-in `// NOSONAR` also works but provides no reason.

---

## Recommended Layered Approach

1. **Detect** all MD5/SHA-1/weak algorithm usages
2. **Score context** using heuristic name analysis
3. **Escalate to CRITICAL** if security-context keywords present
4. **Downgrade to INFO** if non-security context keywords present
5. **Default to MAJOR** when context is ambiguous
6. **Suppress** if `@SafeWeakHash` annotation or `// safe-hash:` comment present

---

## False Positive vs False Negative Trade-off

| Approach | False Positives | False Negatives |
|----------|----------------|----------------|
| Flag everything | High | Low |
| Heuristics only | Medium | Medium |
| Data flow only | Low | Medium |
| Layered (recommended) | Low-Medium | Low |
