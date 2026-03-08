package com.sot.sonar.crypto.rules;

import org.sonar.check.Rule;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.tree.Tree;

import java.util.Collections;
import java.util.List;

/**
 * crypto:WeakPasswordHash
 *
 * Detects password hashing anti-patterns:
 *
 *   A) Any general hash (including SHA-256, SHA-512) applied directly to a
 *      password-named variable via MessageDigest, DigestUtils, or Guava Hashing.
 *
 *   B) PBKDF2 with iteration count < 600,000:
 *      new PBEKeySpec(password, salt, iterationCount, keyLength)
 *      Threshold per OWASP 2025 (PBKDF2-HMAC-SHA256).
 *
 *   C) Unsalted hash on a password-named variable:
 *      MessageDigest called on password input with no salt visible in the call chain.
 *
 * Severity: always CRITICAL. No context escape.
 *
 * Phase 1: stub — detection logic added in Phase 2.
 */
@Rule(key = "WeakPasswordHash")
public class WeakPasswordHashRule extends IssuableSubscriptionVisitor {

    static final int PBKDF2_MIN_ITERATIONS = 600_000;

    static final List<String> PASSWORD_VARIABLE_NAMES = List.of(
        "password", "passwd", "pwd", "credentials", "credential", "userpassword"
    );

    @Override
    public List<Tree.Kind> nodesToVisit() {
        // Phase 2: return List.of(Tree.Kind.METHOD_INVOCATION, Tree.Kind.NEW_CLASS)
        return Collections.emptyList();
    }

    @Override
    public void visitNode(Tree tree) {
        // Phase 2: detection logic here
    }
}
