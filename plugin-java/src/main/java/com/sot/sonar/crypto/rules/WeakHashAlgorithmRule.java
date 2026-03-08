package com.sot.sonar.crypto.rules;

import com.sot.sonar.crypto.util.ContextScorer;
import com.sot.sonar.crypto.util.ContextScorer.Score;
import org.sonar.check.Rule;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.semantic.Type;
import org.sonar.plugins.java.api.tree.ExpressionTree;
import org.sonar.plugins.java.api.tree.IdentifierTree;
import org.sonar.plugins.java.api.tree.LiteralTree;
import org.sonar.plugins.java.api.tree.MemberSelectExpressionTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.NewClassTree;
import org.sonar.plugins.java.api.tree.Tree;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * crypto:WeakHashAlgorithm — detects use of weak/broken hash algorithms.
 *
 * Covers: JDK MessageDigest, Apache Commons DigestUtils,
 *         Guava Hashing, BouncyCastle digest classes.
 *
 * Severity:
 *   SECURITY context  → CRITICAL (noted in message)
 *   NEUTRAL context   → MAJOR (default)
 *   NON_SECURITY      → skipped entirely
 */
@Rule(key = "WeakHashAlgorithm")
public class WeakHashAlgorithmRule extends IssuableSubscriptionVisitor {

    // MessageDigest.getInstance() algorithm names to flag
    private static final Set<String> WEAK_ALGORITHMS = Set.of(
        "md2", "md4", "md5",
        "sha", "sha-0", "sha0",
        "sha-1", "sha1",
        "sha_1"
    );

    // DigestUtils / Guava Hashing method names to flag
    private static final Set<String> DIGEST_UTILS_WEAK_METHODS = Set.of(
        "md2", "md2hex",
        "md5", "md5hex",
        "sha", "shahex",
        "sha1", "sha1hex",
        "crc32"
    );

    // BouncyCastle digest class FQNs
    private static final Set<String> BC_WEAK_DIGEST_FQNS = Set.of(
        "org.bouncycastle.crypto.digests.MD5Digest",
        "org.bouncycastle.crypto.digests.SHA1Digest",
        "org.bouncycastle.crypto.digests.MD4Digest",
        "org.bouncycastle.crypto.digests.MD2Digest"
    );
    private static final Set<String> BC_WEAK_DIGEST_SIMPLE_NAMES = Set.of(
        "MD5Digest", "SHA1Digest", "MD4Digest", "MD2Digest"
    );

    private static final String MESSAGE_DIGEST_FQN = "java.security.MessageDigest";
    private static final String DIGEST_UTILS_FQN   = "org.apache.commons.codec.digest.DigestUtils";
    private static final String GUAVA_HASHING_FQN  = "com.google.common.hash.Hashing";

    @Override
    public List<Tree.Kind> nodesToVisit() {
        return Arrays.asList(Tree.Kind.METHOD_INVOCATION, Tree.Kind.NEW_CLASS);
    }

    @Override
    public void visitNode(Tree tree) {
        if (tree.is(Tree.Kind.NEW_CLASS)) {
            checkBouncyCastle((NewClassTree) tree);
        } else {
            checkMethodInvocation((MethodInvocationTree) tree);
        }
    }

    // --- BouncyCastle: new MD5Digest() etc. ---

    private void checkBouncyCastle(NewClassTree nct) {
        Type type = nct.symbolType();
        boolean isWeak;
        if (!type.isUnknown()) {
            isWeak = BC_WEAK_DIGEST_FQNS.contains(type.fullyQualifiedName());
        } else {
            isWeak = BC_WEAK_DIGEST_SIMPLE_NAMES.contains(simpleTypeName(nct));
        }
        if (!isWeak) return;

        Score ctx = ContextScorer.score(nct);
        if (ctx == Score.NON_SECURITY) return;

        String typeName = simpleTypeName(nct);
        reportIssue(nct, buildMessage(typeName, ctx));
    }

    // --- JDK / Apache Commons / Guava ---

    private void checkMethodInvocation(MethodInvocationTree mit) {
        if (!mit.methodSelect().is(Tree.Kind.MEMBER_SELECT)) return;
        MemberSelectExpressionTree mset = (MemberSelectExpressionTree) mit.methodSelect();
        String methodName = mset.identifier().name();

        // MessageDigest.getInstance("MD5")
        if ("getInstance".equals(methodName) && isOwnerType(mit, MESSAGE_DIGEST_FQN)) {
            checkMessageDigestGetInstance(mit);
            return;
        }

        // DigestUtils.md5() / sha1() etc.
        if (isOwnerType(mit, DIGEST_UTILS_FQN)) {
            if (DIGEST_UTILS_WEAK_METHODS.contains(methodName.toLowerCase(Locale.ROOT))) {
                flagIfNotNonSecurity(mit, methodName);
            }
            return;
        }

        // Hashing.md5() / sha1() / crc32()
        if (isOwnerType(mit, GUAVA_HASHING_FQN)) {
            if (DIGEST_UTILS_WEAK_METHODS.contains(methodName.toLowerCase(Locale.ROOT))) {
                flagIfNotNonSecurity(mit, "Hashing." + methodName);
            }
        }
    }

    private void checkMessageDigestGetInstance(MethodInvocationTree mit) {
        if (mit.arguments().isEmpty()) return;
        ExpressionTree firstArg = mit.arguments().get(0);
        if (!firstArg.is(Tree.Kind.STRING_LITERAL)) return;

        String normalized = ((LiteralTree) firstArg).value()
            .replace("\"", "")
            .toLowerCase(Locale.ROOT);

        if (!WEAK_ALGORITHMS.contains(normalized.replace("-", "").replace("_", ""))) return;

        flagIfNotNonSecurity(mit, ((LiteralTree) firstArg).value().replace("\"", ""));
    }

    private void flagIfNotNonSecurity(MethodInvocationTree mit, String algoName) {
        Score ctx = ContextScorer.score(mit);
        if (ctx == Score.NON_SECURITY) return;
        reportIssue(mit, buildMessage(algoName, ctx));
    }

    private String buildMessage(String algo, Score ctx) {
        String base = String.format(
            "`%s` is a broken or weak hash algorithm and must not be used for cryptographic purposes. " +
            "Use `SHA-256` or stronger.",
            algo);
        if (ctx == Score.SECURITY) {
            return "[SECURITY CONTEXT — CRITICAL] " + base;
        }
        return base;
    }

    // --- Helpers ---

    private boolean isOwnerType(MethodInvocationTree mit, String fqn) {
        Symbol sym = mit.symbol();
        if (!sym.isUnknown()) {
            return fqn.equals(sym.owner().type().fullyQualifiedName());
        }
        if (mit.methodSelect().is(Tree.Kind.MEMBER_SELECT)) {
            ExpressionTree receiver = ((MemberSelectExpressionTree) mit.methodSelect()).expression();
            String simpleName = fqn.substring(fqn.lastIndexOf('.') + 1);
            return simpleName.equals(extractSimpleName(receiver));
        }
        return false;
    }

    private String extractSimpleName(ExpressionTree expr) {
        if (expr.is(Tree.Kind.IDENTIFIER)) return ((IdentifierTree) expr).name();
        if (expr.is(Tree.Kind.MEMBER_SELECT)) return ((MemberSelectExpressionTree) expr).identifier().name();
        return "";
    }

    private String simpleTypeName(NewClassTree nct) {
        Tree id = nct.identifier();
        if (id.is(Tree.Kind.IDENTIFIER)) return ((IdentifierTree) id).name();
        if (id.is(Tree.Kind.MEMBER_SELECT)) return ((MemberSelectExpressionTree) id).identifier().name();
        return "";
    }
}
