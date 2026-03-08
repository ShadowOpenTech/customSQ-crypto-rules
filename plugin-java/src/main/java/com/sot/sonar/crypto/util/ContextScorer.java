package com.sot.sonar.crypto.util;

import org.sonar.plugins.java.api.tree.MethodTree;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.VariableTree;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Scores the security context around a tree node by scanning surrounding
 * variable names, method names, and parameter names.
 *
 * Returns:
 *   SECURITY     — only security keywords detected → escalate severity
 *   NEUTRAL      — no clear signal → use default severity
 *   NON_SECURITY — any non-security keyword detected → skip, no issue raised
 *
 * Non-security keywords win over mixed signals (e.g. "cacheKey" → NON_SECURITY).
 */
public final class ContextScorer {

    public enum Score { SECURITY, NEUTRAL, NON_SECURITY }

    private static final List<String> SECURITY_KEYWORDS = Arrays.asList(
        "password", "passwd", "pwd",
        "auth", "authenticate", "login",
        "token", "secret", "credential", "credentials",
        "session",
        "encrypt", "decrypt", "cipher",
        "sign", "verify", "hmac",
        "salt", "nonce", "apikey"
    );

    private static final List<String> NON_SECURITY_KEYWORDS = Arrays.asList(
        "etag", "cache", "cachekey", "checksum", "fingerprint",
        "uuid", "dedup", "deduplicate", "slug", "filename"
    );

    private ContextScorer() {
    }

    /**
     * Evaluates the security context around the given tree node.
     * Walks up the AST collecting names from enclosing variables and method.
     */
    public static Score score(Tree node) {
        int secCount = 0;
        int nonSecCount = 0;

        Tree current = node.parent();
        while (current != null) {
            if (current.is(Tree.Kind.METHOD)) {
                MethodTree method = (MethodTree) current;
                int[] c = countKeywords(method.simpleName().name());
                secCount += c[0];
                nonSecCount += c[1];
                for (VariableTree param : method.parameters()) {
                    c = countKeywords(param.simpleName().name());
                    secCount += c[0];
                    nonSecCount += c[1];
                }
                break;
            }
            if (current.is(Tree.Kind.VARIABLE)) {
                int[] c = countKeywords(((VariableTree) current).simpleName().name());
                secCount += c[0];
                nonSecCount += c[1];
            }
            current = current.parent();
        }

        if (nonSecCount > 0) return Score.NON_SECURITY;
        if (secCount > 0) return Score.SECURITY;
        return Score.NEUTRAL;
    }

    /** Returns [securityHits, nonSecurityHits] for the given identifier name. */
    private static int[] countKeywords(String name) {
        if (name == null || name.isEmpty()) return new int[]{0, 0};
        String lower = name.toLowerCase(Locale.ROOT);
        int sec = 0, nonSec = 0;
        for (String kw : SECURITY_KEYWORDS) {
            if (lower.contains(kw)) sec++;
        }
        for (String kw : NON_SECURITY_KEYWORDS) {
            if (lower.contains(kw)) nonSec++;
        }
        return new int[]{sec, nonSec};
    }
}
