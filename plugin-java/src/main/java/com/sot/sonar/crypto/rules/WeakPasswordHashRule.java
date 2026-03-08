package com.sot.sonar.crypto.rules;

import org.sonar.check.Rule;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.semantic.Type;
import org.sonar.plugins.java.api.tree.Arguments;
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
 * crypto:WeakPasswordHash — detects password hashing anti-patterns.
 *
 * Sub-pattern A: any general hash (MessageDigest, DigestUtils, Hashing) applied
 *                to a password-named variable.
 * Sub-pattern B: new PBEKeySpec with iteration count < 600,000.
 */
@Rule(key = "WeakPasswordHash")
public class WeakPasswordHashRule extends IssuableSubscriptionVisitor {

    static final int PBKDF2_MIN_ITERATIONS = 600_000;

    static final List<String> PASSWORD_VARIABLE_NAMES = Arrays.asList(
        "password", "passwd", "pwd", "credentials", "credential", "userpassword"
    );

    private static final String PBKDF2_CLASS_FQN = "javax.crypto.spec.PBEKeySpec";
    private static final String PBKDF2_CLASS_SIMPLE = "PBEKeySpec";

    private static final String MESSAGE_DIGEST_FQN = "java.security.MessageDigest";
    private static final String DIGEST_UTILS_FQN = "org.apache.commons.codec.digest.DigestUtils";
    private static final String GUAVA_HASHING_FQN = "com.google.common.hash.Hashing";

    // DigestUtils methods that hash directly (single-call)
    private static final Set<String> DIGEST_UTILS_METHODS = Set.of(
        "md5", "md5Hex", "md2", "md2Hex",
        "sha1", "sha1Hex", "sha", "shaHex",
        "sha256", "sha256Hex", "sha384", "sha384Hex", "sha512", "sha512Hex",
        "sha3_256", "sha3_256Hex", "sha3_384", "sha3_384Hex",
        "sha3_512", "sha3_512Hex"
    );

    @Override
    public List<Tree.Kind> nodesToVisit() {
        return Arrays.asList(Tree.Kind.METHOD_INVOCATION, Tree.Kind.NEW_CLASS);
    }

    @Override
    public void visitNode(Tree tree) {
        if (tree.is(Tree.Kind.NEW_CLASS)) {
            checkPbkdf2((NewClassTree) tree);
        } else {
            checkHashOnPassword((MethodInvocationTree) tree);
        }
    }

    // --- Sub-pattern B: PBKDF2 iteration count ---

    private void checkPbkdf2(NewClassTree nct) {
        if (!isPbkdf2Class(nct)) return;

        Arguments args = nct.arguments();
        if (args.size() < 3) return;

        // First arg should be the password (char[])
        if (!isPasswordNamed(args.get(0))) return;

        // Third arg is the iteration count
        ExpressionTree iterArg = args.get(2);
        if (!iterArg.is(Tree.Kind.INT_LITERAL)) return;

        String raw = ((LiteralTree) iterArg).value().replace("_", "");
        try {
            int iterations = Integer.parseInt(raw);
            if (iterations < PBKDF2_MIN_ITERATIONS) {
                reportIssue(iterArg, String.format(
                    "PBKDF2 iteration count of %,d is insufficient. Use at least %,d iterations (OWASP 2025 for PBKDF2-HMAC-SHA256).",
                    iterations, PBKDF2_MIN_ITERATIONS));
            }
        } catch (NumberFormatException ignored) {
            // not a simple integer literal we can parse
        }
    }

    private boolean isPbkdf2Class(NewClassTree nct) {
        Type type = nct.symbolType();
        if (!type.isUnknown()) {
            return PBKDF2_CLASS_FQN.equals(type.fullyQualifiedName());
        }
        // Fallback: simple name check
        return PBKDF2_CLASS_SIMPLE.equals(simpleTypeName(nct));
    }

    // --- Sub-pattern A: general hash on password variable ---

    private void checkHashOnPassword(MethodInvocationTree mit) {
        if (!mit.methodSelect().is(Tree.Kind.MEMBER_SELECT)) return;
        MemberSelectExpressionTree mset = (MemberSelectExpressionTree) mit.methodSelect();
        String methodName = mset.identifier().name();

        // DigestUtils.*(passwordArg)
        if (isOwnerType(mit, DIGEST_UTILS_FQN) && DIGEST_UTILS_METHODS.contains(methodName)) {
            if (!mit.arguments().isEmpty() && isPasswordNamed(mit.arguments().get(0))) {
                reportIssue(mit, buildMessageA(methodName));
            }
            return;
        }

        // MessageDigest.digest(passwordBytes)
        if (isOwnerType(mit, MESSAGE_DIGEST_FQN) && "digest".equals(methodName)) {
            if (!mit.arguments().isEmpty() && isPasswordArgument(mit.arguments().get(0))) {
                reportIssue(mit, buildMessageA("MessageDigest.digest"));
            }
        }
    }

    private String buildMessageA(String method) {
        return String.format(
            "`%s` must not be used to hash passwords directly. Use `Argon2`, `bcrypt`, `scrypt`, " +
            "or `PBKDF2` with >= %,d iterations and a random salt.",
            method, PBKDF2_MIN_ITERATIONS);
    }

    // --- Helpers ---

    /**
     * Checks if the method invocation's owner type matches the given FQN.
     * Falls back to simple name matching when semantic info is unavailable.
     */
    private boolean isOwnerType(MethodInvocationTree mit, String fqn) {
        Symbol sym = mit.symbol();
        if (!sym.isUnknown()) {
            return fqn.equals(sym.owner().type().fullyQualifiedName());
        }
        // Fallback: check the receiver expression's simple name
        if (mit.methodSelect().is(Tree.Kind.MEMBER_SELECT)) {
            ExpressionTree receiver = ((MemberSelectExpressionTree) mit.methodSelect()).expression();
            String simpleName = fqn.substring(fqn.lastIndexOf('.') + 1);
            return simpleName.equals(extractSimpleName(receiver));
        }
        return false;
    }

    /** True if the expression or its immediate receiver is password-named. */
    private boolean isPasswordArgument(ExpressionTree expr) {
        // password.getBytes() → check "password"
        if (expr.is(Tree.Kind.METHOD_INVOCATION)) {
            ExpressionTree sel = ((MethodInvocationTree) expr).methodSelect();
            if (sel.is(Tree.Kind.MEMBER_SELECT)) {
                return isPasswordNamed(((MemberSelectExpressionTree) sel).expression());
            }
        }
        return isPasswordNamed(expr);
    }

    private boolean isPasswordNamed(ExpressionTree expr) {
        String name = extractSimpleName(expr);
        if (name == null) return false;
        String lower = name.toLowerCase(Locale.ROOT);
        return PASSWORD_VARIABLE_NAMES.stream().anyMatch(lower::contains);
    }

    private String extractSimpleName(ExpressionTree expr) {
        if (expr.is(Tree.Kind.IDENTIFIER)) {
            return ((IdentifierTree) expr).name();
        }
        if (expr.is(Tree.Kind.MEMBER_SELECT)) {
            return ((MemberSelectExpressionTree) expr).identifier().name();
        }
        return null;
    }

    private String simpleTypeName(NewClassTree nct) {
        Tree id = nct.identifier();
        if (id.is(Tree.Kind.IDENTIFIER)) return ((IdentifierTree) id).name();
        if (id.is(Tree.Kind.MEMBER_SELECT)) return ((MemberSelectExpressionTree) id).identifier().name();
        return "";
    }
}
