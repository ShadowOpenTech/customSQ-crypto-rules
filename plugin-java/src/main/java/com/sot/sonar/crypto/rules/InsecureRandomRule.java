package com.sot.sonar.crypto.rules;

import com.sot.sonar.crypto.util.ContextScorer;
import com.sot.sonar.crypto.util.ContextScorer.Score;
import org.sonar.check.Rule;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.semantic.Type;
import org.sonar.plugins.java.api.tree.IdentifierTree;
import org.sonar.plugins.java.api.tree.MemberSelectExpressionTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.NewClassTree;
import org.sonar.plugins.java.api.tree.Tree;

import java.util.Arrays;
import java.util.List;

/**
 * crypto:InsecureRandom
 *
 * Detects:
 *   - new Random()       → only when output is in a security context
 *   - Math.random()      → only when output is in a security context
 *   - new SecureRandom(seed) with any argument → always (fixed seed)
 */
@Rule(key = "InsecureRandom")
public class InsecureRandomRule extends IssuableSubscriptionVisitor {

    private static final String RANDOM_FQN        = "java.util.Random";
    private static final String SECURE_RANDOM_FQN = "java.security.SecureRandom";
    private static final String MATH_FQN           = "java.lang.Math";

    @Override
    public List<Tree.Kind> nodesToVisit() {
        return Arrays.asList(Tree.Kind.NEW_CLASS, Tree.Kind.METHOD_INVOCATION);
    }

    @Override
    public void visitNode(Tree tree) {
        if (tree.is(Tree.Kind.NEW_CLASS)) {
            checkNewClass((NewClassTree) tree);
        } else {
            checkMethodInvocation((MethodInvocationTree) tree);
        }
    }

    // --- new Random() / new SecureRandom(seed) ---

    private void checkNewClass(NewClassTree nct) {
        Type type = nct.symbolType();

        if (!type.isUnknown()) {
            String fqn = type.fullyQualifiedName();

            // new SecureRandom(seed) — always flag, regardless of context
            if (SECURE_RANDOM_FQN.equals(fqn) && !nct.arguments().isEmpty()) {
                reportIssue(nct,
                    "`SecureRandom` must not be initialized with a fixed seed — " +
                    "this produces deterministic output. Remove the seed argument.");
                return;
            }

            // new Random() — only flag in security context
            if (RANDOM_FQN.equals(fqn)) {
                flagIfSecurityContext(nct, "`java.util.Random` is not cryptographically secure. " +
                    "Use `SecureRandom` for security-sensitive values.");
            }
        } else {
            // Fallback name-based check
            String simpleName = simpleTypeName(nct);
            if ("SecureRandom".equals(simpleName) && !nct.arguments().isEmpty()) {
                reportIssue(nct,
                    "`SecureRandom` must not be initialized with a fixed seed — " +
                    "this produces deterministic output. Remove the seed argument.");
            } else if ("Random".equals(simpleName)) {
                flagIfSecurityContext(nct, "`java.util.Random` is not cryptographically secure. " +
                    "Use `SecureRandom` for security-sensitive values.");
            }
        }
    }

    // --- Math.random() ---

    private void checkMethodInvocation(MethodInvocationTree mit) {
        if (!mit.methodSelect().is(Tree.Kind.MEMBER_SELECT)) return;
        MemberSelectExpressionTree mset = (MemberSelectExpressionTree) mit.methodSelect();
        if (!"random".equals(mset.identifier().name())) return;

        Symbol sym = mit.symbol();
        boolean isMathRandom;
        if (!sym.isUnknown()) {
            isMathRandom = MATH_FQN.equals(sym.owner().type().fullyQualifiedName());
        } else {
            // Fallback: check receiver name is "Math"
            isMathRandom = "Math".equals(extractSimpleName(mset.expression()));
        }

        if (isMathRandom) {
            flagIfSecurityContext(mit, "`Math.random()` is not cryptographically secure. " +
                "Use `SecureRandom` for security-sensitive values.");
        }
    }

    // --- Helpers ---

    private void flagIfSecurityContext(Tree tree, String message) {
        Score ctx = ContextScorer.score(tree);
        if (ctx == Score.SECURITY) {
            reportIssue(tree, message);
        }
        // NEUTRAL → skip (no issue), NON_SECURITY → skip
    }

    private String simpleTypeName(NewClassTree nct) {
        Tree id = nct.identifier();
        if (id.is(Tree.Kind.IDENTIFIER)) return ((IdentifierTree) id).name();
        if (id.is(Tree.Kind.MEMBER_SELECT)) return ((MemberSelectExpressionTree) id).identifier().name();
        return "";
    }

    private String extractSimpleName(Tree expr) {
        if (expr.is(Tree.Kind.IDENTIFIER)) return ((IdentifierTree) expr).name();
        if (expr.is(Tree.Kind.MEMBER_SELECT)) return ((MemberSelectExpressionTree) expr).identifier().name();
        return "";
    }
}
