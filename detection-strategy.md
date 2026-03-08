# Detection Strategy

## The Core Problem

Static analysis cannot always determine *intent* from syntax alone. The goal is to use contextual signals to reduce false positives and prioritize true security risks — without introducing custom suppression mechanisms beyond SonarQube's built-in `// NOSONAR`.

---

## Strategy 1: Heuristic Name Analysis

Scan surrounding variable names, method names, parameter names, and class names for keywords.

### Escalate to CRITICAL if near:
- `password`, `passwd`, `pwd`
- `auth`, `authenticate`, `login`
- `token`, `secret`, `credential`
- `encrypt`, `decrypt`, `cipher`
- `sign`, `verify`, `hmac`
- `hash`, `digest` (in a security context)

### Skip entirely if near:
- `etag`, `cache`, `cacheKey`
- `fingerprint`, `checksum`
- `uuid`, `random`, `randomId`
- `deduplicate`, `dedup`
- `slug`, `id`, `filename`

Accumulate signals as a score rather than a binary match — multiple security-context keywords increase confidence. Non-security context with no issue raised = no noise for developers.

---

## Strategy 2: Data Flow Analysis (Light)

Track where the output is used:

| Output destination | Action |
|--------------------|--------|
| Assigned to `password` / `token` / `salt` / `nonce` field | Escalate |
| Passed into auth/login method | Escalate |
| Assigned to `cache` / `etag` / `id` variable | Skip |

Used by `crypto:InsecureRandom` to determine if `new Random()` output is in a security context.
Used by `crypto:WeakPasswordHash` to detect when a hash input variable is password-named.

---

## Recommended Layered Approach

1. **Detect** all matching API calls (weak algorithm, PRNG, etc.)
2. **Score context** using heuristic name analysis (`ContextScorer`)
3. **Escalate to CRITICAL** if security-context keywords present
4. **Default to MAJOR** when context is ambiguous
5. **Skip entirely** if non-security context keywords present — no issue raised
6. Developer uses `// NOSONAR` to suppress if the issue is a false positive

---

## False Positive vs False Negative Trade-off

| Approach | False Positives | False Negatives |
|----------|----------------|----------------|
| Flag everything | High | Low |
| Heuristics only | Medium | Medium |
| Data flow only | Low | Medium |
| Layered (this approach) | Low | Low |

---

## Suppression

Only SonarQube's built-in `// NOSONAR` is supported. No custom annotation or comment convention.
The skip-in-non-security-context behaviour reduces the need for suppression in the first place.
