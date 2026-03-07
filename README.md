# SonarQube Custom Crypto Rules — Ideation

Design notes for custom SonarQube rules targeting weak and broken cryptographic practices, developed in the context of CBOM's cryptographic asset detection goals.

## Relationship to CBOM

IBM's `sonar-cryptography` plugin (CBOMkit-hyperion) generates CBOM inventory from source code.
These rules complement that by **flagging policy violations** as SonarQube issues — actionable findings developers see in their normal workflow.

The two approaches are compatible:
- CBOM = inventory (what crypto exists)
- These rules = enforcement (what crypto is not allowed / needs justification)

## Files

- [detection-strategy.md](./detection-strategy.md) — Context disambiguation (security vs non-security use)
- [algorithms-coverage.md](./algorithms-coverage.md) — Full algorithm list with Java API patterns
- [rule-design.md](./rule-design.md) — 6 proposed rules with severity tiers and suppression conventions
