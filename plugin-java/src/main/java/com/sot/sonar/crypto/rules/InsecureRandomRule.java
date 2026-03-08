package com.sot.sonar.crypto.rules;

import org.sonar.check.Rule;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.tree.Tree;

import java.util.Collections;
import java.util.List;

/**
 * crypto:InsecureRandom
 *
 * Detects insecure random number generation:
 *   - new Random()       → only when output flows to a security-context variable
 *   - Math.random()      → only when output flows to a security-context variable
 *   - new SecureRandom(seed) with any argument → always flag (fixed seed)
 *
 * Severity:
 *   Output in security context   → CRITICAL
 *   Fixed-seed SecureRandom      → CRITICAL
 *   No security context detected → skip (no issue raised)
 *
 * Phase 1: stub — detection logic added in Phase 4.
 */
@Rule(key = "InsecureRandom")
public class InsecureRandomRule extends IssuableSubscriptionVisitor {

    @Override
    public List<Tree.Kind> nodesToVisit() {
        // Phase 4: return List.of(Tree.Kind.NEW_CLASS, Tree.Kind.METHOD_INVOCATION)
        return Collections.emptyList();
    }

    @Override
    public void visitNode(Tree tree) {
        // Phase 4: detection logic here
    }
}
