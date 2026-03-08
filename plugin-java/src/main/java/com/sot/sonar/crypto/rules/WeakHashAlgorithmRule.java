package com.sot.sonar.crypto.rules;

import org.sonar.check.Rule;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.tree.Tree;

import java.util.Collections;
import java.util.List;

/**
 * crypto:WeakHashAlgorithm
 *
 * Detects use of weak/broken hash algorithms (MD5, SHA-1, etc.) across:
 *   - JDK MessageDigest
 *   - Apache Commons DigestUtils
 *   - Guava Hashing
 *   - BouncyCastle MD5Digest / SHA1Digest / MD4Digest
 *
 * Severity is context-adjusted via ContextScorer:
 *   SECURITY context  → CRITICAL
 *   NEUTRAL context   → MAJOR (default)
 *   NON_SECURITY      → skip (no issue raised)
 *
 * Phase 1: stub — detection logic added in Phase 3.
 */
@Rule(key = "WeakHashAlgorithm")
public class WeakHashAlgorithmRule extends IssuableSubscriptionVisitor {

    @Override
    public List<Tree.Kind> nodesToVisit() {
        // Phase 3: return List.of(Tree.Kind.METHOD_INVOCATION, Tree.Kind.NEW_CLASS)
        return Collections.emptyList();
    }

    @Override
    public void visitNode(Tree tree) {
        // Phase 3: detection logic here
    }
}
