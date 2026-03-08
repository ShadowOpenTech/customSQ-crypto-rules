package com.sot.sonar.crypto.util;

import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.MethodTree;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.VariableTree;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Scores the security context around a method invocation by scanning
 * surrounding variable names, method names, parameter names, and class names.
 *
 * Returns:
 *   SECURITY     — security-context keywords detected → escalate to CRITICAL
 *   NEUTRAL      — no clear signal → use default severity (MAJOR)
 *   NON_SECURITY — non-security keywords detected → skip, no issue raised
 */
public final class ContextScorer {

    public enum Score { SECURITY, NEUTRAL, NON_SECURITY }

    private static final List<String> SECURITY_KEYWORDS = Arrays.asList(
        "password", "passwd", "pwd", "auth", "authenticate", "login",
        "token", "secret", "credential", "credentials",
        "encrypt", "decrypt", "cipher",
        "sign", "verify", "hmac", "hash", "digest"
    );

    private static final List<String> NON_SECURITY_KEYWORDS = Arrays.asList(
        "etag", "cache", "cachekey", "checksum", "fingerprint",
        "uuid", "dedup", "deduplicate", "slug", "filename", "id"
    );

    private ContextScorer() {
    }

    /**
     * Evaluates the context around the given tree node.
     * Walks up the AST collecting names from enclosing method and local variables.
     */
    public static Score score(Tree node) {
        int points = 0;

        Tree current = node.parent();
        while (current != null) {
            if (current.is(Tree.Kind.METHOD)) {
                MethodTree method = (MethodTree) current;
                points += scoreIdentifier(method.simpleName().name());
                for (var param : method.parameters()) {
                    points += scoreIdentifier(param.simpleName().name());
                }
                break;
            }
            if (current.is(Tree.Kind.VARIABLE)) {
                VariableTree variable = (VariableTree) current;
                points += scoreIdentifier(variable.simpleName().name());
            }
            current = current.parent();
        }

        if (points > 0) return Score.SECURITY;
        if (points < 0) return Score.NON_SECURITY;
        return Score.NEUTRAL;
    }

    private static int scoreIdentifier(String name) {
        if (name == null || name.isEmpty()) return 0;
        String lower = name.toLowerCase(Locale.ROOT);
        int score = 0;
        for (String keyword : SECURITY_KEYWORDS) {
            if (lower.contains(keyword)) score++;
        }
        for (String keyword : NON_SECURITY_KEYWORDS) {
            if (lower.contains(keyword)) score--;
        }
        return score;
    }
}
